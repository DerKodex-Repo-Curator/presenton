import base64
import hashlib
import hmac
import secrets
from typing import Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
from models.sql.key_value import KeyValueSqlModel
from utils.legacy_config import read_legacy_config
from utils.db_utils import secure_sqlite_database_permissions


SESSION_COOKIE_NAME = "presenton_session"
SESSION_TTL_SECONDS = 60 * 60 * 24 * 30
AUTH_SETTINGS_ID = UUID("b4eacdb7-7ac2-4ac6-9fa7-51776f00cf14")


def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")


def _base64url_decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded.encode("utf-8"))


def verify_legacy_password_hash(password: str, encoded_hash: str) -> bool:
    """Verify hashes produced by the pre-database single-user auth system."""
    try:
        algorithm, iterations_str, salt_encoded, digest_encoded = encoded_hash.split("$")
        if algorithm != "pbkdf2_sha256":
            return False

        iterations = int(iterations_str)
        salt = _base64url_decode(salt_encoded)
        expected_digest = _base64url_decode(digest_encoded)
        actual_digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
        )
        return hmac.compare_digest(actual_digest, expected_digest)
    except Exception:
        return False


async def get_or_create_auth_secret(
    session: AsyncSession, *, rotate: bool = False
) -> str:
    """Persist the deployment key in a private DB row, importing the old key once.

    The same key encrypts existing API keys and cloud credentials: an upgrade
    must preserve it even when provider settings were already migrated earlier.
    """
    row = await session.get(
        KeyValueSqlModel, AUTH_SETTINGS_ID,
        with_for_update=rotate, populate_existing=True,
    )
    if row is not None and not rotate:
        secret = row.value.get("AUTH_SECRET_KEY")
        if not isinstance(secret, str) or not secret:
            raise RuntimeError("Database authentication signing key is invalid")
        return secret
    legacy = read_legacy_config() if row is None else {}
    if session.bind is not None:
        secure_sqlite_database_permissions(str(session.bind.url))
    secret = legacy.get("AUTH_SECRET_KEY") if not rotate else None
    if not isinstance(secret, str) or not secret:
        secret = _base64url_encode(secrets.token_bytes(32))
    if row is None:
        try:
            async with session.begin_nested():
                session.add(KeyValueSqlModel(
                    id=AUTH_SETTINGS_ID,
                    key="deployment_auth",
                    value={"AUTH_SECRET_KEY": secret},
                ))
                await session.flush()
        except IntegrityError:
            await session.rollback()
            return await get_or_create_auth_secret(session)
    else:
        row.value = {"AUTH_SECRET_KEY": secret}
    await session.commit()
    return secret


def get_legacy_admin_credentials() -> tuple[Optional[str], Optional[str]]:
    """Used only when no database accounts exist."""
    config = read_legacy_config()
    username = config.get("AUTH_USERNAME")
    password_hash = config.get("AUTH_PASSWORD_HASH")
    return (
        username.strip() if isinstance(username, str) and username.strip() else None,
        password_hash if isinstance(password_hash, str) and password_hash else None,
    )
