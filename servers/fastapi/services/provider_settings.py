import logging
import os
from typing import Any

from sqlalchemy import create_engine, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from models.sql.provider_settings import ProviderSettings
from utils.datetime_utils import get_current_utc_datetime
from utils.db_utils import get_database_url_and_connect_args, to_sync_sqlalchemy_url
from utils.legacy_config import read_legacy_config
from utils.user_config import initial_provider_config, normalize_provider_config, update_env_with_provider_config


logger = logging.getLogger(__name__)

PROVIDER_SETTINGS_ID = 1
CODEX_MANAGED_FIELDS = {
    "CODEX_ACCESS_TOKEN",
    "CODEX_REFRESH_TOKEN",
    "CODEX_TOKEN_EXPIRES",
    "CODEX_ACCOUNT_ID",
    "CODEX_USERNAME",
    "CODEX_EMAIL",
    "CODEX_IS_PRO",
}
PRESENTON_STATUS_FIELDS = {
    "PRESENTON_CONNECTED",
    "PRESENTON_EMAIL",
}
OAUTH_MANAGED_FIELDS = CODEX_MANAGED_FIELDS | PRESENTON_STATUS_FIELDS
EMPTY_VALUE_PRESERVED_FIELDS = {
    "OPEN_WEBUI_IMAGE_URL",
    "OPEN_WEBUI_IMAGE_API_KEY",
    "CODEX_MODEL",
}
OPTIONAL_ADVANCED_FIELDS = {
    "LLM_GENERATION_PROFILE",
    "LLM_MAX_OUTPUT_TOKENS",
    "LLM_REASONING_MODE",
    "LLM_REASONING_EFFORT",
    "LLM_REASONING_BUDGET_TOKENS",
    "DISABLE_THINKING",
    "EXTENDED_REASONING",
    "OPENROUTER_PROVIDER_ORDER",
    "OPENROUTER_ALLOW_FALLBACKS",
    "OPENROUTER_REQUIRE_PARAMETERS",
    "OPENROUTER_DATA_COLLECTION",
    "OPENROUTER_ZDR",
}


def sanitize_provider_settings(config: dict[str, Any]) -> dict[str, Any]:
    """Keep provider/runtime settings and exclude every legacy auth field."""
    return {
        key: value
        for key, value in config.items()
        if not key.upper().startswith("AUTH_")
    }


def merge_provider_settings(
    existing: dict[str, Any], incoming: dict[str, Any]
) -> dict[str, Any]:
    """Preserve the previous settings API's patch and managed-token behavior."""
    sanitized = sanitize_provider_settings(incoming)
    merged = {**sanitize_provider_settings(existing), **sanitized}

    for key in OAUTH_MANAGED_FIELDS:
        if key in existing:
            merged[key] = existing[key]
        else:
            merged.pop(key, None)

    for key in EMPTY_VALUE_PRESERVED_FIELDS:
        if not sanitized.get(key) and key in existing:
            merged[key] = existing[key]

    for key in OPTIONAL_ADVANCED_FIELDS:
        if key in sanitized and sanitized[key] in (None, "", []):
            merged.pop(key, None)

    return merged


async def migrate_provider_settings_from_file(session: AsyncSession) -> dict[str, Any]:
    """Import only when no DB settings exist; never write the legacy file."""
    row = await session.get(ProviderSettings, PROVIDER_SETTINGS_ID)

    if row is None:
        legacy_config = initial_provider_config(read_legacy_config())
        row = ProviderSettings(
            id=PROVIDER_SETTINGS_ID,
            config=sanitize_provider_settings(legacy_config),
        )
        session.add(row)
        try:
            await session.commit()
        except IntegrityError:
            await session.rollback()
            return await migrate_provider_settings_from_file(session)
        await session.refresh(row)
        logger.info("Initialized database provider settings from legacy configuration and environment defaults.")
    else:
        sanitized = sanitize_provider_settings(dict(row.config or {}))
        if sanitized != row.config:
            row.config = sanitized
            row.updated_at = get_current_utc_datetime()
            await session.commit()

    config = dict(row.config or {})
    return config


async def get_provider_settings(session: AsyncSession) -> dict[str, Any]:
    row = await session.get(ProviderSettings, PROVIDER_SETTINGS_ID)
    if row is None:
        return await migrate_provider_settings_from_file(session)
    return sanitize_provider_settings(dict(row.config or {}))


async def save_provider_settings(
    session: AsyncSession, incoming: dict[str, Any]
) -> dict[str, Any]:
    # Row locks serialize server databases. The timestamp comparison also
    # protects SQLite, where SELECT FOR UPDATE is not supported.
    for _ in range(5):
        row = await session.get(
            ProviderSettings, PROVIDER_SETTINGS_ID,
            with_for_update=True, populate_existing=True,
        )
        if row is None:
            await migrate_provider_settings_from_file(session)
            continue
        config = normalize_provider_config(
            merge_provider_settings(dict(row.config or {}), incoming)
        )
        statement = update(ProviderSettings).where(
            ProviderSettings.id == PROVIDER_SETTINGS_ID,
            ProviderSettings.updated_at == row.updated_at,
        ).values(config=config, updated_at=get_current_utc_datetime())
        result = await session.execute(
            statement, execution_options={"synchronize_session": False}
        )
        if result.rowcount == 1:
            await session.commit()
            session.expire(row)
            update_env_with_provider_config(config)
            return config
        await session.rollback()
    raise RuntimeError("Provider settings changed concurrently; retry the update")


def _sync_engine():
    database_url = os.getenv("DATABASE_URL") or get_database_url_and_connect_args()[0]
    return create_engine(to_sync_sqlalchemy_url(database_url), poolclass=NullPool)


def patch_provider_settings_sync(patch: dict[str, Any]) -> None:
    """OAuth refresh patches only its managed fields, never a stale JSON copy."""
    if set(patch) - (CODEX_MANAGED_FIELDS | {"CODEX_MODEL"}):
        raise ValueError("Only Codex-managed fields can be changed by token refresh")
    engine = _sync_engine()
    try:
        for _ in range(5):
            with Session(engine) as session:
                row = session.get(ProviderSettings, PROVIDER_SETTINGS_ID, with_for_update=True)
                if row is None:
                    raise RuntimeError("Provider settings have not been initialized")
                config = {**dict(row.config or {}), **patch}
                statement = update(ProviderSettings).where(
                    ProviderSettings.id == PROVIDER_SETTINGS_ID,
                    ProviderSettings.updated_at == row.updated_at,
                ).values(config=config, updated_at=get_current_utc_datetime())
                result = session.execute(
                    statement, execution_options={"synchronize_session": False}
                )
                if result.rowcount == 1:
                    session.commit()
                    return
        raise RuntimeError("Provider settings changed concurrently; retry token refresh")
    finally:
        engine.dispose()
