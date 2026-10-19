import asyncio
from datetime import timedelta
import json
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from api.v1.auth.config import get_or_create_auth_secret
from api.v1.provider_config import PROVIDER_CONFIG_ROUTER
from models.sql.user import User
from models.sql.key_value import KeyValueSqlModel
from models.sql.presenton_cloud_provider import PresentonCloudProvider
from models.sql.provider_settings import ProviderSettings
from services.api_keys import encrypt_api_key, reveal_api_key, build_api_key
from services.database import get_async_session
from services.provider_settings import migrate_provider_settings_from_file, save_provider_settings, patch_provider_settings_sync
from services.presenton_cloud import _encrypt_token, get_valid_presenton_access_token
from utils.datetime_utils import get_current_utc_datetime
from utils.user_config import update_env_with_provider_config


@pytest.fixture
def database(monkeypatch, tmp_path):
    url = f"sqlite+aiosqlite:///{tmp_path / 'settings.db'}"
    monkeypatch.setenv("DATABASE_URL", url)
    monkeypatch.setenv("USER_CONFIG_PATH", str(tmp_path / "userConfig.json"))
    engine = create_async_engine(url)
    async def create():
        async with engine.begin() as connection:
            for model in (User, KeyValueSqlModel, ProviderSettings, PresentonCloudProvider):
                await connection.run_sync(model.__table__.create)
    asyncio.run(create())
    yield async_sessionmaker(engine, expire_on_commit=False)
    asyncio.run(engine.dispose())


def test_database_survives_restart_and_deleted_legacy_file(database, monkeypatch, tmp_path):
    path = tmp_path / "userConfig.json"
    path.write_text(json.dumps({"LLM": "openai", "OPENAI_API_KEY": "original-key", "AUTH_SECRET_KEY": "legacy-secret"}))
    async def first_start():
        async with database() as session:
            await migrate_provider_settings_from_file(session)
            assert await get_or_create_auth_secret(session) == "legacy-secret"
            await save_provider_settings(session, {"OPENAI_API_KEY": "database-key"})
    asyncio.run(first_start())
    assert json.loads(path.read_text())["OPENAI_API_KEY"] == "original-key"
    path.unlink()
    monkeypatch.setenv("OPENAI_API_KEY", "stale-env-key")
    async def second_start():
        async with database() as session:
            config = await migrate_provider_settings_from_file(session)
            assert config["OPENAI_API_KEY"] == "database-key"
            assert await get_or_create_auth_secret(session) == "legacy-secret"
            await save_provider_settings(session, {"OPENAI_API_KEY": None})
            update_env_with_provider_config(await migrate_provider_settings_from_file(session))
    asyncio.run(second_start())
    import os
    assert "OPENAI_API_KEY" not in os.environ
    assert not path.exists()


def test_legacy_signing_secret_keeps_existing_api_keys_and_cloud_tokens_decryptable(database, tmp_path):
    from models.sql.api_key import ApiKey
    import uuid
    path = tmp_path / "userConfig.json"
    path.write_text('{"AUTH_SECRET_KEY":"previous-deployment-secret"}')
    token = build_api_key("0123456789abcdef", "s" * 40)
    key = ApiKey(id="0123456789abcdef", secret_hash="unused", token_encrypted=encrypt_api_key(token, "previous-deployment-secret"), user_id=uuid.uuid4(), created_by_id=uuid.uuid4(), expires_at=get_current_utc_datetime() + timedelta(days=1))
    async def run():
        async with database() as session:
            assert await get_or_create_auth_secret(session) == "previous-deployment-secret"
            session.add(PresentonCloudProvider(id=1, issuer="https://api.presenton.test", subject="admin", email="admin@example.com", access_token_encrypted=_encrypt_token("cloud-secret", "previous-deployment-secret"), token_expires_at=get_current_utc_datetime() + timedelta(days=1)))
            await session.commit()
        path.unlink()
        async with database() as session:
            assert await reveal_api_key(session, key) == token
            value, _ = await get_valid_presenton_access_token(session, issuer="https://api.presenton.test")
            assert value == "cloud-secret"
    asyncio.run(run())


def test_oauth_refresh_patches_database_without_overwriting_settings_or_json(database, monkeypatch, tmp_path):
    path = tmp_path / "userConfig.json"
    path.write_text('{"CUSTOM_MODEL":"stale-file-model","CODEX_ACCESS_TOKEN":"stale-token"}')
    original = path.read_bytes()
    async def seed():
        async with database() as session:
            await save_provider_settings(session, {"LLM": "custom", "CUSTOM_MODEL": "current-model", "CUSTOM_LLM_URL": "http://provider:8080/v1"})
    asyncio.run(seed())
    from utils.user_config import save_codex_tokens_to_database
    monkeypatch.setenv("CODEX_ACCESS_TOKEN", "refreshed-token")
    monkeypatch.setenv("CODEX_REFRESH_TOKEN", "refreshed-refresh-token")
    save_codex_tokens_to_database()
    async def check():
        async with database() as session:
            row = await session.get(ProviderSettings, 1)
            assert row.config["CUSTOM_MODEL"] == "current-model"
            assert row.config["CODEX_ACCESS_TOKEN"] == "refreshed-token"
    asyncio.run(check())
    assert path.read_bytes() == original
    monkeypatch.delenv("CODEX_ACCESS_TOKEN", raising=False)
    monkeypatch.delenv("CODEX_REFRESH_TOKEN", raising=False)
    monkeypatch.delenv("CODEX_MODEL", raising=False)
    save_codex_tokens_to_database(include_model=True)
    async def check_logout():
        async with database() as session:
            row = await session.get(ProviderSettings, 1)
            assert row.config["CODEX_ACCESS_TOKEN"] is None
            assert row.config["CODEX_REFRESH_TOKEN"] is None
            assert row.config["CODEX_MODEL"] is None
    asyncio.run(check_logout())


def test_runtime_endpoint_is_authenticated_and_never_exposes_secrets(database, monkeypatch):
    from api.v1.auth.users import read_user_from_cookie
    app = FastAPI()
    app.include_router(PROVIDER_CONFIG_ROUTER)
    async def session_override():
        async with database() as session:
            yield session
    app.dependency_overrides[get_async_session] = session_override
    app.dependency_overrides[read_user_from_cookie] = lambda: None
    monkeypatch.delenv("DISABLE_AUTH", raising=False)
    client = TestClient(app)
    assert client.get("/api/v1/config/runtime").status_code == 401
    async def seed():
        async with database() as session:
            session.add(ProviderSettings(id=1, config={"LLM": "openai", "OPENAI_API_KEY": "provider-secret", "CODEX_ACCESS_TOKEN": "token-secret", "AUTH_SECRET_KEY": "auth-secret", "PRIVATE_UNKNOWN_KEY": "unknown-secret", "LLM_MAX_OUTPUT_TOKENS": 8192}))
            await session.commit()
    asyncio.run(seed())
    app.dependency_overrides[read_user_from_cookie] = lambda: object()
    response = client.get("/api/v1/config/runtime")
    assert response.status_code == 200
    config = response.json()["config"]
    assert config["OPENAI_API_KEY"] == "__configured__"
    assert config["CODEX_ACCESS_TOKEN"] == "__configured__"
    assert config["LLM_MAX_OUTPUT_TOKENS"] == 8192
    assert "AUTH_SECRET_KEY" not in config
    assert "PRIVATE_UNKNOWN_KEY" not in config
    assert "secret" not in response.text


def test_admin_save_preserves_tokens_refreshed_concurrently(database):
    from sqlalchemy.sql.dml import Update
    async def run():
        async with database() as session:
            session.add(ProviderSettings(id=1, config={"LLM": "custom", "CUSTOM_MODEL": "before", "CODEX_ACCESS_TOKEN": "old-token"}))
            await session.commit()
            execute = session.execute
            refreshed = False
            async def racing_execute(statement, *args, **kwargs):
                nonlocal refreshed
                if isinstance(statement, Update) and not refreshed:
                    refreshed = True
                    patch_provider_settings_sync({"CODEX_ACCESS_TOKEN": "new-token"})
                return await execute(statement, *args, **kwargs)
            session.execute = racing_execute
            saved = await save_provider_settings(session, {"CUSTOM_MODEL": "after"})
            assert saved["CUSTOM_MODEL"] == "after"
            assert saved["CODEX_ACCESS_TOKEN"] == "new-token"
    asyncio.run(run())


def test_existing_browser_session_survives_signing_key_migration(database, tmp_path):
    import uuid
    from api.v1.auth.users import VersionedJWTStrategy, get_jwt_strategy, UserManager, UsernameUserDatabase
    from models.sql.user import User
    path = tmp_path / "userConfig.json"
    path.write_text('{"AUTH_SECRET_KEY":"existing-session-secret-at-least-32-bytes"}')
    async def run():
        async with database() as session:
            user = User(id=uuid.uuid4(), username="admin", hashed_password="existing-hash", is_superuser=True, is_active=True, is_verified=True)
            session.add(user)
            await session.commit()
            token = await VersionedJWTStrategy(secret="existing-session-secret-at-least-32-bytes", lifetime_seconds=3600).write_token(user)
            await get_or_create_auth_secret(session)
        path.unlink()
        async with database() as session:
            strategy = await get_jwt_strategy(session)
            authenticated = await strategy.read_token(token, UserManager(UsernameUserDatabase(session)))
            assert authenticated is not None
            assert authenticated.username == "admin"
    asyncio.run(run())


def test_parallel_startup_uses_one_persisted_signing_key(database):
    async def create_key():
        async with database() as session:
            return await get_or_create_auth_secret(session)
    async def run():
        keys = await asyncio.gather(create_key(), create_key())
        assert keys[0] == keys[1]
    asyncio.run(run())


def test_readonly_legacy_import_and_backup_recovery(database, tmp_path):
    path = tmp_path / "userConfig.json"
    path.write_text("corrupt primary")
    backup = tmp_path / "userConfig.json.bak"
    backup.write_text('{"LLM":"custom","CUSTOM_MODEL":"saved-model","AUTH_SECRET_KEY":"preserved-secret"}')
    async def run():
        with patch("utils.user_config_store.os.chmod", side_effect=PermissionError("read-only mount")), patch("utils.user_config_store.update_user_config_file", side_effect=AssertionError("Legacy file must not be written")):
            async with database() as session:
                config = await migrate_provider_settings_from_file(session)
                assert config["CUSTOM_MODEL"] == "saved-model"
                assert await get_or_create_auth_secret(session) == "preserved-secret"
    asyncio.run(run())
    assert path.read_text() == "corrupt primary"
    assert json.loads(backup.read_text())["AUTH_SECRET_KEY"] == "preserved-secret"


def test_legacy_account_import_does_not_depend_on_json_after_upgrade(database, monkeypatch, tmp_path):
    from unittest.mock import AsyncMock
    from sqlalchemy import select
    from api.v1.auth import bootstrap
    from api.v1.auth.users import PASSWORD_HELPER
    path = tmp_path / "userConfig.json"
    password_hash = PASSWORD_HELPER.hash("existing-password")
    path.write_text(json.dumps({"AUTH_USERNAME": "legacy-admin", "AUTH_PASSWORD_HASH": password_hash, "AUTH_SECRET_KEY": "legacy-signing-key"}))
    original = path.read_bytes()
    monkeypatch.setattr(bootstrap, "async_session_maker", database)
    monkeypatch.setattr(bootstrap, "_backfill_legacy_ownership", AsyncMock())
    for name in ("AUTH_USERNAME", "AUTH_PASSWORD", "AUTH_OVERRIDE_FROM_ENV", "RESET_AUTH"):
        monkeypatch.delenv(name, raising=False)
    async def run():
        await bootstrap.bootstrap_database_admin()
        async with database() as session:
            admin = await session.scalar(select(User))
            assert admin.username == "legacy-admin"
            assert PASSWORD_HELPER.verify_and_update("existing-password", admin.hashed_password)[0]
            assert await get_or_create_auth_secret(session) == "legacy-signing-key"
        assert path.read_bytes() == original
        path.unlink()
        await bootstrap.bootstrap_database_admin()
        async with database() as session:
            assert len(list(await session.scalars(select(User)))) == 1
    asyncio.run(run())


def test_telemetry_uses_database_with_deployment_opt_out(database, monkeypatch):
    app = FastAPI()
    app.include_router(PROVIDER_CONFIG_ROUTER)
    async def session_override():
        async with database() as session:
            yield session
    app.dependency_overrides[get_async_session] = session_override
    async def seed():
        async with database() as session:
            await save_provider_settings(session, {"DISABLE_ANONYMOUS_TRACKING": False})
    asyncio.run(seed())
    client = TestClient(app)
    monkeypatch.delenv("DISABLE_ANONYMOUS_TRACKING", raising=False)
    assert client.get("/api/v1/config/telemetry").json() == {"telemetryEnabled": True}
    monkeypatch.setenv("DISABLE_ANONYMOUS_TRACKING", "true")
    assert client.get("/api/v1/config/telemetry").json() == {"telemetryEnabled": False}


@pytest.mark.parametrize("uri", [False, True])
def test_local_database_and_journals_have_private_permissions(database, tmp_path, uri):
    import os
    import stat
    if os.name == "nt":
        pytest.skip("Windows uses filesystem ACLs")
    from utils.db_utils import secure_sqlite_database_permissions
    path = tmp_path / "settings.db"
    journal = tmp_path / "settings.db-wal"
    journal.write_text("journal-secret")
    path.chmod(0o644)
    journal.chmod(0o644)
    url = f"sqlite+aiosqlite:///file:{path}?uri=true" if uri else f"sqlite+aiosqlite:///{path}"
    secure_sqlite_database_permissions(url)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(journal.stat().st_mode) == 0o600
