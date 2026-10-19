import base64
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from enums.image_provider import ImageProvider
from models.user_config import UserConfig
from services.image_generation_service import ImageGenerationService
from utils.get_env import get_gpt_image_2_quality_env
from utils.image_provider import get_selected_image_provider
from utils.model_availability import _check_image_provider_configuration
from utils.user_config import update_env_with_provider_config


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
@pytest.mark.parametrize("quality", [None, "low", "medium", "high"])
async def test_gpt_image_2_generates_and_saves_base64_image(monkeypatch, tmp_path, quality):
    monkeypatch.setenv("IMAGE_PROVIDER", "gpt-image-2")
    monkeypatch.setenv("DISABLE_IMAGE_GENERATION", "false")
    if quality:
        monkeypatch.setenv("GPT_IMAGE_2_QUALITY", quality)
    else:
        monkeypatch.delenv("GPT_IMAGE_2_QUALITY", raising=False)
    client = SimpleNamespace(images=SimpleNamespace(generate=AsyncMock(
        return_value=SimpleNamespace(data=[SimpleNamespace(
            b64_json=base64.b64encode(b"generated-image").decode()
        )])
    )))
    service = ImageGenerationService(str(tmp_path))

    with patch("services.image_generation_service.AsyncOpenAI", return_value=client):
        output = await service.image_gen_func("landscape", str(tmp_path), (1600, 900))

    client.images.generate.assert_awaited_once_with(
        model="gpt-image-2", prompt="landscape", n=1,
        quality=quality or "medium", size="1536x1024",
    )
    assert Path(output).read_bytes() == b"generated-image"


@pytest.mark.parametrize("legacy_quality, expected", [("standard", "medium"), ("hd", "high")])
def test_migrates_saved_dalle3_selection(legacy_quality, expected):
    config = UserConfig(IMAGE_PROVIDER="dall-e-3", DALL_E_3_QUALITY=legacy_quality)
    assert config.IMAGE_PROVIDER == "gpt-image-2"
    assert config.GPT_IMAGE_2_QUALITY == expected
    assert "DALL_E_3_QUALITY" not in config.model_dump()


def test_legacy_selection_preserves_explicit_new_quality():
    config = UserConfig(IMAGE_PROVIDER="dall-e-3", GPT_IMAGE_2_QUALITY="low")
    assert config.GPT_IMAGE_2_QUALITY == "low"


def test_migrates_legacy_environment(monkeypatch):
    monkeypatch.setenv("IMAGE_PROVIDER", "dall-e-3")
    monkeypatch.setenv("DALL_E_3_QUALITY", "hd")
    monkeypatch.delenv("GPT_IMAGE_2_QUALITY", raising=False)
    assert get_selected_image_provider() == ImageProvider.GPT_IMAGE_2
    assert get_gpt_image_2_quality_env() == "high"
    monkeypatch.setenv("GPT_IMAGE_2_QUALITY", "low")
    assert get_gpt_image_2_quality_env() == "low"


def test_gpt_image_2_requires_openai_key(monkeypatch):
    monkeypatch.setenv("IMAGE_PROVIDER", "gpt-image-2")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with pytest.raises(Exception, match="OPENAI_API_KEY must be provided"):
        _check_image_provider_configuration()
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    _check_image_provider_configuration()


def test_gpt_image_2_quality_config_round_trip(monkeypatch, tmp_path):
    monkeypatch.setattr(os, "environ", os.environ.copy())
    config_path = tmp_path / "config.json"
    monkeypatch.setenv("USER_CONFIG_PATH", str(config_path))
    monkeypatch.setenv("IMAGE_PROVIDER", "gpt-image-2")
    monkeypatch.delenv("GPT_IMAGE_2_QUALITY", raising=False)
    config_path.write_text(json.dumps(
        UserConfig(IMAGE_PROVIDER="gpt-image-2", GPT_IMAGE_2_QUALITY="high").model_dump()
    ))
    config = UserConfig.model_validate_json(config_path.read_text())
    update_env_with_provider_config(config.model_dump())
    assert config.IMAGE_PROVIDER == "gpt-image-2"
    assert config.GPT_IMAGE_2_QUALITY == "high"
    assert os.getenv("GPT_IMAGE_2_QUALITY") == "high"
