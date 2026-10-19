"""Browser-safe views of authoritative database configuration."""
import os
import re

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from api.v1.auth.users import read_user_from_cookie
from models.sql.user import User
from models.user_config import UserConfig
from services.database import get_async_session
from services.provider_settings import get_provider_settings
from utils.get_env import is_disable_auth_enabled

PROVIDER_CONFIG_ROUTER = APIRouter(prefix="/api/v1/config", tags=["Configuration"])
SECRET_FIELD = re.compile(
    r"(?:API_KEY|ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN|ACCESS_TOKEN|REFRESH_TOKEN|PASSWORD)$",
    re.I,
)


@PROVIDER_CONFIG_ROUTER.get("/runtime")
async def runtime_config(
    user: User | None = Depends(read_user_from_cookie),
    session: AsyncSession = Depends(get_async_session),
):
    if not is_disable_auth_enabled() and user is None:
        raise HTTPException(401, "Unauthorized")
    # An allowlist also excludes legacy auth fields and unknown private keys.
    config = UserConfig.model_validate(
        await get_provider_settings(session)
    ).model_dump(exclude_unset=True)
    return {"config": {
        key: "__configured__" if SECRET_FIELD.search(key) and value else value
        for key, value in config.items()
    }}


@PROVIDER_CONFIG_ROUTER.get("/telemetry")
async def telemetry_config(session: AsyncSession = Depends(get_async_session)):
    config = await get_provider_settings(session)
    disabled = str(config.get("DISABLE_ANONYMOUS_TRACKING", "")).lower() in {"true", "1", "yes", "on"}
    disabled = disabled or os.getenv("DISABLE_ANONYMOUS_TRACKING", "").lower() in {"true", "1", "yes", "on"}
    return {"telemetryEnabled": not disabled}
