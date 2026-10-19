from models.sql.key_value import KeyValueSqlModel
import asyncio
import json
from unittest.mock import patch

import pytest

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from api.v1.admin.router import API_V1_ADMIN_ROUTER
from api.v1.auth.config import SESSION_COOKIE_NAME
from api.v1.auth.router import API_V1_AUTH_ROUTER
from api.v1.auth.users import PASSWORD_HELPER
from models.sql.api_key import ApiKey
from models.sql.presenton_cloud_provider import PresentonCloudProvider
from models.sql.provider_settings import ProviderSettings
from models.sql.user import User
from services.database import get_async_session
from services.presenton_cloud import store_presenton_credentials
from utils.get_env import get_presenton_oauth_issuer


@pytest.fixture(autouse=True)
def isolate_runtime_environment():
    # Settings updates and startup load provider values into os.environ directly.
    # Restore those application-owned writes as well as monkeypatched values.
    with patch.dict("os.environ"):
        yield


def _build_client(tmp_path, lifespan=None) -> tuple[TestClient, object]:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'auth.db'}")
    session_maker = async_sessionmaker(engine, expire_on_commit=False)

    async def create_user_table():
        async with engine.begin() as connection:
            await connection.run_sync(User.__table__.create)
            await connection.run_sync(KeyValueSqlModel.__table__.create)
            await connection.run_sync(ApiKey.__table__.create)
            await connection.run_sync(ProviderSettings.__table__.create)
            await connection.run_sync(PresentonCloudProvider.__table__.create)

    asyncio.run(create_user_table())

    async def override_session():
        async with session_maker() as session:
            yield session

    app = FastAPI(lifespan=lifespan)
    app.include_router(API_V1_AUTH_ROUTER)
    app.include_router(API_V1_ADMIN_ROUTER)
    app.dependency_overrides[get_async_session] = override_session
    return TestClient(app), engine


def test_admin_can_read_and_update_settings_with_legacy_flag_disabled(monkeypatch, tmp_path):
    monkeypatch.setenv("USER_CONFIG_PATH", str(tmp_path / "userConfig.json"))
    monkeypatch.setenv("CAN_CHANGE_KEYS", "false")
    monkeypatch.delenv("DISABLE_AUTH", raising=False)
    client, engine = _build_client(tmp_path)
    try:
        client.post("/api/v1/auth/setup", json={"username": "admin", "password": "secret123"})
        client.post("/api/v1/auth/login", json={"username": "admin", "password": "secret123"})
        saved = client.put("/api/v1/admin/provider-settings", json={"LLM": "openai", "OPENAI_API_KEY": "admin-only-key"})
        assert saved.status_code == 200
        response = client.get("/api/v1/admin/provider-settings")
        assert response.status_code == 200
        assert response.json()["OPENAI_API_KEY"] == "admin-only-key"
    finally:
        asyncio.run(engine.dispose())


@pytest.mark.parametrize("authenticated", [False, True])
def test_provider_keys_require_admin_session(monkeypatch, tmp_path, authenticated):
    monkeypatch.setenv("USER_CONFIG_PATH", str(tmp_path / "userConfig.json"))
    monkeypatch.delenv("DISABLE_AUTH", raising=False)
    client, engine = _build_client(tmp_path)
    try:
        client.post("/api/v1/auth/setup", json={"username": "admin", "password": "secret123"})
        client.post("/api/v1/auth/login", json={"username": "admin", "password": "secret123"})
        client.put("/api/v1/admin/provider-settings", json={"LLM": "openai", "OPENAI_API_KEY": "admin-only-key"})
        client.post("/api/v1/admin/users", json={"username": "member", "password": "secret456"})
        client.cookies.clear()
        if authenticated:
            client.post("/api/v1/auth/login", json={"username": "member", "password": "secret456"})
        expected = 403 if authenticated else 401
        for response in (
            client.get("/api/v1/admin/provider-settings"),
            client.put("/api/v1/admin/provider-settings", json={"OPENAI_API_KEY": "replacement"}),
        ):
            assert response.status_code == expected
            assert "admin-only-key" not in response.text
        client.cookies.clear()
        client.post("/api/v1/auth/login", json={"username": "admin", "password": "secret123"})
        assert client.get("/api/v1/admin/provider-settings").json()["OPENAI_API_KEY"] == "admin-only-key"
    finally:
        asyncio.run(engine.dispose())


@pytest.mark.parametrize("provider_config", [{}, {"LLM": "openai"}, {"LLM": "ollama", "OLLAMA_MODEL": "missing-model"}])
def test_missing_provider_config_does_not_block_startup_status_or_setup(monkeypatch, tmp_path, provider_config):
    from api import lifespan

    monkeypatch.setenv("APP_DATA_DIRECTORY", str(tmp_path))
    monkeypatch.setenv("USER_CONFIG_PATH", str(tmp_path / "userConfig.json"))
    monkeypatch.setenv("CAN_CHANGE_KEYS", "false")
    monkeypatch.delenv("DISABLE_AUTH", raising=False)
    for field in ("LLM", "OPENAI_API_KEY", "OPENAI_MODEL", "IMAGE_PROVIDER", "OLLAMA_MODEL"):
        monkeypatch.delenv(field, raising=False)
    (tmp_path / "userConfig.json").write_text(json.dumps(provider_config))
    for field, value in provider_config.items():
        monkeypatch.setenv(field, value)

    async def no_op(*args):
        pass

    # Keep the real lifecycle and config migration; isolate unrelated template
    # installation and database initialization already performed by this fixture.
    for name in ("migrate_database_on_startup", "create_db_and_tables", "bootstrap_database_admin", "import_default_templates_on_startup", "fail_interrupted_async_tasks"):
        monkeypatch.setattr(lifespan, name, no_op)
    client, engine = _build_client(tmp_path, lifespan.app_lifespan)
    monkeypatch.setattr(lifespan, "async_session_maker", async_sessionmaker(engine, expire_on_commit=False))
    monkeypatch.setattr(lifespan, "dispose_engines", engine.dispose)
    with client:
        status = client.get("/api/v1/auth/status")
        assert status.status_code == 200
        assert status.json()["configured"] is False
        setup = client.post("/api/v1/auth/setup", json={"username": "admin", "password": "secret123"})
        assert setup.status_code == 200
        assert client.get("/api/v1/auth/status").json()["configured"] is True


def test_login_sets_http_only_jwt_cookie_for_username_only_account(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("USER_CONFIG_PATH", str(tmp_path / "userConfig.json"))
    monkeypatch.delenv("DISABLE_AUTH", raising=False)

    client, engine = _build_client(tmp_path)
    setup = client.post(
        "/api/v1/auth/setup",
        json={"username": "admin", "password": "secret123"},
    )
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "ADMIN", "password": "secret123"},
    )

    assert setup.status_code == 200
    assert response.status_code == 200
    payload = response.json()
    assert payload["configured"] is True
    assert payload["authenticated"] is True
    assert payload["username"] == "admin"
    assert "access_token" not in payload
    assert SESSION_COOKIE_NAME in response.cookies
    assert "HttpOnly" in response.headers["set-cookie"]

    asyncio.run(engine.dispose())


def test_admin_can_assign_normal_user_key_for_rest_api(monkeypatch, tmp_path):
    monkeypatch.setenv("USER_CONFIG_PATH", str(tmp_path / "userConfig.json"))
    monkeypatch.delenv("DISABLE_AUTH", raising=False)
    client, engine = _build_client(tmp_path)
    client.post(
        "/api/v1/auth/setup",
        json={"username": "admin", "password": "secret123"},
    )
    client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "secret123"},
    )
    user_response = client.post(
        "/api/v1/admin/users",
        json={"username": "api-user", "password": "secret456"},
    )
    token_response = client.post(
        "/api/v1/admin/api-keys",
        json={
            "user_id": user_response.json()["id"],
            "label": "Automation",
            "expiry_days": 90,
        },
    )
    token = token_response.json()["token"]
    client.cookies.clear()

    response = client.get(
        "/api/v1/auth/verify",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert user_response.status_code == 201
    assert token_response.status_code == 201
    assert token.startswith("sk-presenton-")
    assert not token.startswith("sk-presenton-mcp-")
    assert response.status_code == 200
    assert response.json()["method"] == "api_key"
    assert response.json()["role"] == "user"
    assert response.json()["username"] == "api-user"

    legacy_response = client.get(
        "/api/v1/auth/verify",
        headers={"Authorization": "Bearer sk-presenton-legacy-plaintext"},
    )
    assert legacy_response.status_code == 401

    asyncio.run(engine.dispose())


def test_legacy_six_character_password_can_still_log_in(monkeypatch, tmp_path):
    monkeypatch.setenv("USER_CONFIG_PATH", str(tmp_path / "userConfig.json"))
    monkeypatch.delenv("DISABLE_AUTH", raising=False)
    client, engine = _build_client(tmp_path)

    async def seed_legacy_admin():
        session_maker = async_sessionmaker(engine, expire_on_commit=False)
        async with session_maker() as session:
            session.add(
                User(
                    username="legacy-admin",
                    hashed_password=PASSWORD_HELPER.hash("123456"),
                    is_active=True,
                    is_verified=True,
                    is_superuser=True,
                    admin_slot="primary",
                )
            )
            await session.commit()

    asyncio.run(seed_legacy_admin())
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "legacy-admin", "password": "123456"},
    )

    assert response.status_code == 200
    assert response.json()["role"] == "admin"
    asyncio.run(engine.dispose())


def test_repeated_failed_logins_are_not_rate_limited(monkeypatch, tmp_path):
    monkeypatch.setenv("USER_CONFIG_PATH", str(tmp_path / "userConfig.json"))
    monkeypatch.delenv("DISABLE_AUTH", raising=False)
    client, engine = _build_client(tmp_path)
    client.post(
        "/api/v1/auth/setup",
        json={"username": "rate-admin", "password": "secret123"},
    )
    for _ in range(10):
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "rate-admin", "password": "wrong-password"},
        )
        assert response.status_code == 401
    asyncio.run(engine.dispose())


def test_database_rejects_a_second_primary_administrator(monkeypatch, tmp_path):
    monkeypatch.setenv("USER_CONFIG_PATH", str(tmp_path / "userConfig.json"))
    client, engine = _build_client(tmp_path)
    client.post(
        "/api/v1/auth/setup",
        json={"username": "first-admin", "password": "secret123"},
    )

    async def insert_second_admin():
        session_maker = async_sessionmaker(engine, expire_on_commit=False)
        async with session_maker() as session:
            session.add(
                User(
                    username="second-admin",
                    hashed_password=PASSWORD_HELPER.hash("secret456"),
                    is_active=True,
                    is_verified=True,
                    is_superuser=True,
                    admin_slot="primary",
                )
            )
            try:
                await session.commit()
            except IntegrityError:
                await session.rollback()
                return True
        return False

    assert asyncio.run(insert_second_admin()) is True
    asyncio.run(engine.dispose())


def test_admin_provider_settings_include_safe_global_presenton_status(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("USER_CONFIG_PATH", str(tmp_path / "userConfig.json"))
    client, engine = _build_client(tmp_path)
    client.post(
        "/api/v1/auth/setup",
        json={"username": "admin", "password": "secret123"},
    )
    client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "secret123"},
    )

    async def seed_provider():
        session_maker = async_sessionmaker(engine, expire_on_commit=False)
        async with session_maker() as session:
            await store_presenton_credentials(
                session,
                issuer=get_presenton_oauth_issuer(),
                subject="cloud-admin",
                email="cloud-admin@example.com",
                access_token="user.jwt.signature",
                expires_in=3600,
            )

    asyncio.run(seed_provider())
    response = client.get("/api/v1/admin/provider-settings")

    assert response.status_code == 200
    assert response.json()["PRESENTON_CONNECTED"] is True
    assert response.json()["PRESENTON_EMAIL"] == "cloud-admin@example.com"
    assert "PRESENTON_SCOPES" not in response.json()
    assert "PRESENTON_ACCESS_TOKEN" not in response.json()
    assert "PRESENTON_REFRESH_TOKEN" not in response.json()
    asyncio.run(engine.dispose())
