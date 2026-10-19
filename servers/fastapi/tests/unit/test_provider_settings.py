import asyncio

from models.sql.user import User
from services.provider_settings import (
    merge_provider_settings,
    migrate_provider_settings_from_file,
    sanitize_provider_settings,
)
from utils.user_config_store import read_user_config_file, update_user_config_file


class ProviderSettingsSession:
    def __init__(self):
        self.row = None

    async def get(self, _model, _key):
        return self.row

    def add(self, row):
        self.row = row

    async def commit(self):
        return None

    async def refresh(self, _row):
        return None


def test_user_table_has_username_and_no_email_column():
    columns = set(User.__table__.columns.keys())

    assert "username" in columns
    assert "email" not in columns


def test_provider_settings_exclude_all_legacy_auth_fields():
    assert sanitize_provider_settings(
        {
            "LLM": "openai",
            "AUTH_USERNAME": "admin",
            "AUTH_PASSWORD": "plain",
            "AUTH_PASSWORD_HASH": "hash",
            "AUTH_SECRET_KEY": "jwt-secret",
        }
    ) == {"LLM": "openai"}


def test_reset_advanced_settings_removes_only_optional_overrides():
    existing = {
        "LLM": "openrouter",
        "OPENROUTER_API_KEY": "key",
        "OPENROUTER_MODEL": "openai/gpt-4o",
        "LLM_MAX_OUTPUT_TOKENS": 65536,
        "LLM_REASONING_MODE": "enabled",
        "OPENROUTER_PROVIDER_ORDER": ["groq"],
    }

    merged = merge_provider_settings(
        existing,
        {
            "LLM_MAX_OUTPUT_TOKENS": "",
            "LLM_REASONING_MODE": "",
            "OPENROUTER_PROVIDER_ORDER": [],
        },
    )

    assert merged == {
        "LLM": "openrouter",
        "OPENROUTER_API_KEY": "key",
        "OPENROUTER_MODEL": "openai/gpt-4o",
    }


def test_startup_imports_legacy_config_without_rewriting_file(
    monkeypatch, tmp_path
):
    path = tmp_path / "userConfig.json"
    monkeypatch.setenv("USER_CONFIG_PATH", str(path))
    update_user_config_file(
        str(path),
        lambda _: {
            "AUTH_USERNAME": "admin",
            "AUTH_PASSWORD_HASH": "legacy-hash",
            "AUTH_SECRET_KEY": "jwt-secret",
            "LLM": "openai",
            "OPENAI_API_KEY": "provider-key",
        },
    )
    session = ProviderSettingsSession()

    migrated = asyncio.run(migrate_provider_settings_from_file(session))

    assert migrated["LLM"] == "openai"
    assert migrated["OPENAI_API_KEY"] == "provider-key"
    assert "AUTH_SECRET_KEY" not in migrated
    assert session.row.config == migrated
    assert read_user_config_file(str(path)) == {
        "LLM": "openai",
        "OPENAI_API_KEY": "provider-key",
        "AUTH_USERNAME": "admin",
        "AUTH_PASSWORD_HASH": "legacy-hash",
        "AUTH_SECRET_KEY": "jwt-secret",
    }


def test_existing_database_wins_over_legacy_file_and_environment(monkeypatch, tmp_path):
    from models.sql.provider_settings import ProviderSettings
    path = tmp_path / "userConfig.json"
    path.write_text('{"OPENAI_API_KEY":"stale-file-key","LLM":"google"}')
    original = path.read_bytes()
    monkeypatch.setenv("USER_CONFIG_PATH", str(path))
    monkeypatch.setenv("OPENAI_API_KEY", "stale-environment-key")
    session = ProviderSettingsSession()
    session.row = ProviderSettings(id=1, config={"LLM": "openai", "OPENAI_API_KEY": "database-key"})
    assert asyncio.run(migrate_provider_settings_from_file(session)) == session.row.config
    assert path.read_bytes() == original


def test_first_import_uses_environment_only_for_missing_legacy_values(monkeypatch, tmp_path):
    path = tmp_path / "userConfig.json"
    path.write_text('{"LLM":"custom","CUSTOM_MODEL":"saved-model","DISABLE_IMAGE_GENERATION":false}')
    monkeypatch.setenv("USER_CONFIG_PATH", str(path))
    monkeypatch.setenv("CUSTOM_MODEL", "environment-model")
    monkeypatch.setenv("CUSTOM_LLM_URL", "http://provider:8080/v1")
    monkeypatch.setenv("DISABLE_IMAGE_GENERATION", "true")
    session = ProviderSettingsSession()
    config = asyncio.run(migrate_provider_settings_from_file(session))
    assert config["CUSTOM_MODEL"] == "saved-model"
    assert config["CUSTOM_LLM_URL"] == "http://provider:8080/v1"
    assert config["DISABLE_IMAGE_GENERATION"] is False


def test_new_deployment_does_not_create_legacy_file(monkeypatch, tmp_path):
    path = tmp_path / "userConfig.json"
    monkeypatch.setenv("USER_CONFIG_PATH", str(path))
    monkeypatch.setenv("LLM", "custom")
    monkeypatch.setenv("CUSTOM_MODEL", "model")
    monkeypatch.setenv("CUSTOM_LLM_URL", "http://provider:8080/v1")
    config = asyncio.run(migrate_provider_settings_from_file(ProviderSettingsSession()))
    assert config["CUSTOM_MODEL"] == "model"
    assert not path.exists()


def test_corrupt_legacy_config_is_not_silently_imported_as_empty(monkeypatch, tmp_path):
    import pytest
    path = tmp_path / "userConfig.json"
    path.write_text("invalid json")
    monkeypatch.setenv("USER_CONFIG_PATH", str(path))
    session = ProviderSettingsSession()
    with pytest.raises(RuntimeError, match="legacy configuration"):
        asyncio.run(migrate_provider_settings_from_file(session))
    assert session.row is None
