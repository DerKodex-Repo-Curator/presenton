import asyncio
import json

import pytest
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from api import middlewares
from api.middlewares import SessionAuthMiddleware
from api.v1.admin.router import API_V1_ADMIN_ROUTER
from api.v1.auth.assets import mount_app_data_assets
from api.v1.auth.desktop import DESKTOP_COOKIE_NAME, DESKTOP_TOKEN_HEADER
from api.v1.auth.router import API_V1_AUTH_ROUTER
from api.v1.auth.users import read_user_from_cookie
from api.v1.ppt.endpoints import images
from models.sql.api_key import ApiKey
from models.sql.presenton_cloud_provider import PresentonCloudProvider
from models.sql.provider_settings import ProviderSettings
from models.sql.user import User
from services.database import get_async_session
from utils.asset_directory_utils import resolve_app_path_to_filesystem

TOKEN = "a" * 64


@pytest.fixture
def desktop_client(monkeypatch, tmp_path):
    for key, value in {
        "PRESENTON_ELECTRON": "true", "PRESENTON_DESKTOP_TOKEN": TOKEN,
        "PRESENTON_DESKTOP_ORIGINS": "http://127.0.0.1:40001,http://127.0.0.1:40000",
        "DISABLE_AUTH": "true", "CAN_CHANGE_KEYS": "true",
        "NEXT_PUBLIC_URL": "http://127.0.0.1:40001",
        "NEXT_PUBLIC_FAST_API": "http://127.0.0.1:40000",
        "APP_DATA_DIRECTORY": str(tmp_path),
        "USER_CONFIG_PATH": str(tmp_path / "userConfig.json"),
    }.items():
        monkeypatch.setenv(key, value)
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'fastapi.db'}")
    sessions = async_sessionmaker(engine, expire_on_commit=False)

    async def initialize():
        async with engine.begin() as connection:
            for table in (User, ApiKey, ProviderSettings, PresentonCloudProvider):
                await connection.run_sync(table.__table__.create)
        async with sessions() as session:
            session.add(ProviderSettings(id=1, config={"LLM": "openai", "OPENAI_API_KEY": "saved-provider-key"}))
            await session.commit()

    asyncio.run(initialize())

    async def override_session():
        async with sessions() as session:
            yield session

    async def no_cloud(*_args, **_kwargs):
        return None

    monkeypatch.setattr(middlewares, "async_session_maker", sessions)
    monkeypatch.setattr(middlewares, "maybe_proxy_presenton_cloud_request", no_cloud)
    app = FastAPI()
    app.include_router(API_V1_ADMIN_ROUTER)
    app.include_router(API_V1_AUTH_ROUTER)
    app.include_router(images.IMAGES_ROUTER, prefix="/api/v1/ppt")
    app.dependency_overrides[get_async_session] = override_session
    app.dependency_overrides[read_user_from_cookie] = lambda: None
    mount_app_data_assets(app, str(tmp_path))
    app.add_middleware(CORSMiddleware, allow_origins=["http://127.0.0.1:40001"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
    app.add_middleware(SessionAuthMiddleware)
    with TestClient(app, base_url="http://127.0.0.1:40000") as client:
        yield client, tmp_path
    asyncio.run(engine.dispose())


@pytest.mark.parametrize("path", ["/api/v1/auth/status", "/api/v1/auth/verify", "/api/v1/admin/provider-settings", "/docs", "/openapi.json", "/app_data/userConfig.json"])
def test_anonymous_desktop_calls_do_not_inherit_admin(desktop_client, path):
    client, _ = desktop_client
    assert client.get(path).status_code == 401


@pytest.mark.parametrize("headers", [
    {"origin": "https://attacker.example"}, {"origin": "null"},
    {"host": "attacker.example:40000"}, {"host": "127.0.0.1:40002"},
    {"host": "attacker.example", "x-forwarded-host": "127.0.0.1:40000"},
])
def test_valid_credential_cannot_bypass_origin_or_host(desktop_client, headers):
    client, _ = desktop_client
    assert client.get("/api/v1/auth/status", headers={DESKTOP_TOKEN_HEADER: TOKEN, **headers}).status_code == 403


def test_stale_or_missing_startup_credential_fails_closed(desktop_client, monkeypatch):
    client, _ = desktop_client
    assert client.get("/api/v1/auth/status", headers={DESKTOP_TOKEN_HEADER: "b" * 64}).status_code == 401
    monkeypatch.delenv("PRESENTON_DESKTOP_TOKEN")
    assert client.get("/api/v1/auth/status", headers={DESKTOP_TOKEN_HEADER: TOKEN}).status_code == 503


def test_settings_attack_is_denied_and_authorized_no_login_save_works(desktop_client):
    client, root = desktop_client
    config = {"LLM": "custom", "CUSTOM_LLM_URL": "https://attacker.example/v1", "CUSTOM_MODEL": "test", "CUSTOM_LLM_API_KEY": "key"}
    for media_type in ("text/plain", "application/json"):
        assert client.put("/api/v1/admin/provider-settings", content=json.dumps(config), headers={"content-type": media_type}).status_code == 401
    headers = {DESKTOP_TOKEN_HEADER: TOKEN, "Origin": "http://127.0.0.1:40001"}
    status = client.get("/api/v1/auth/status", headers=headers)
    assert status.json()["role"] == "admin"
    saved = client.put("/api/v1/admin/provider-settings", json=config, headers=headers)
    assert saved.status_code == 200
    assert not (root / "userConfig.json").exists()
    assert client.get("/api/v1/admin/provider-settings", headers=headers).json()["CUSTOM_MODEL"] == "test"
    assert client.get("/api/v1/admin/provider-settings", headers=headers).json()["CUSTOM_LLM_URL"] == config["CUSTOM_LLM_URL"]


@pytest.mark.parametrize("path", [
    "/app_data/userConfig.json", "/app_data/userConfig.json.bak", "/app_data/fastapi.db", "/app_data/logs/fastapi-server.log",
    "/app_data/images/%252e%252e/userConfig.json", "/app_data/images/%2e%2e/userConfig.json",
])
def test_private_files_are_not_assets_even_for_desktop_admin(desktop_client, path):
    client, root = desktop_client
    (root / "userConfig.json").write_text('{"AUTH_SECRET_KEY":"secret"}')
    (root / "userConfig.json.bak").write_text("backup secret")
    (root / "logs").mkdir(exist_ok=True)
    (root / "logs" / "fastapi-server.log").write_text("log secret")
    response = client.get(path, headers={DESKTOP_TOKEN_HEADER: TOKEN})
    assert response.status_code == 404
    assert "secret" not in response.text
    assert resolve_app_path_to_filesystem(path) is None


def test_assets_work_and_symlink_escape_is_denied(desktop_client):
    client, root = desktop_client
    headers = {"Cookie": f"{DESKTOP_COOKIE_NAME}={TOKEN}"}
    for directory in ("images", "fonts", "templates", "uploads", "exports", "pptx-to-html", "pptx-to-json"):
        (root / directory / "asset.txt").write_text("ordinary asset")
        assert client.get(f"/app_data/{directory}/asset.txt", headers=headers).text == "ordinary asset"
    private = root / "userConfig.json"
    private.write_text("private")
    (root / "images" / "alias.txt").symlink_to(private)
    assert client.get("/app_data/images/alias.txt", headers=headers).status_code == 404
    assert resolve_app_path_to_filesystem("/app_data/images/alias.txt") is None


def test_only_trusted_origin_can_preflight(desktop_client):
    client, _ = desktop_client
    headers = {"Origin": "http://127.0.0.1:40001", "Access-Control-Request-Method": "PUT", "Access-Control-Request-Headers": "content-type"}
    assert client.options("/api/v1/admin/provider-settings", headers=headers).status_code == 200
    headers["Origin"] = "https://attacker.example"
    assert client.options("/api/v1/admin/provider-settings", headers=headers).status_code == 403


def test_anonymous_simple_get_does_not_consume_image_quota(desktop_client, monkeypatch):
    client, _ = desktop_client
    calls = []

    async def generate(_self, prompt):
        calls.append(prompt.prompt)
        return "https://images.example/result.png"

    monkeypatch.setattr(images.ImageGenerationService, "generate_image", generate)
    url = "/api/v1/ppt/images/generate?prompt=ordinary"
    assert client.get(url).status_code == 401
    assert calls == []
    assert client.get(url, headers={DESKTOP_TOKEN_HEADER: TOKEN}).status_code == 200
    assert calls == ["ordinary"]
