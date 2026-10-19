"""Provider configuration normalization and process-local runtime projection.

The database owns saved values. Environment variables seed a new installation;
legacy JSON is read only by the one-time migration, never by runtime consumers.
"""
import logging
import os

from pydantic import ValidationError

from models.user_config import UserConfig

logger = logging.getLogger(__name__)
PROVIDER_FIELDS = set(UserConfig.model_fields)


def normalize_provider_config(config: dict) -> dict:
    data = dict(config)
    order = data.get("OPENROUTER_PROVIDER_ORDER")
    if isinstance(order, str):
        data["OPENROUTER_PROVIDER_ORDER"] = [part.strip() for part in order.split(",") if part.strip()]
    normalized = UserConfig.model_validate(data).model_dump(exclude_unset=True)
    return {**{key: value for key, value in data.items() if key not in PROVIDER_FIELDS and key != "DALL_E_3_QUALITY"}, **normalized}


def provider_config_from_environment() -> dict:
    data = {key: os.environ[key] for key in PROVIDER_FIELDS | {"DALL_E_3_QUALITY"} if os.environ.get(key, "").strip()}
    while True:
        try:
            return normalize_provider_config(data)
        except ValidationError as error:
            invalid = {item["loc"][0] for item in error.errors()}
            if not invalid.intersection(data):
                raise
            for key in invalid:
                data.pop(key, None)
            # Validation messages include input values, which can be secrets.
            logger.warning("Ignoring invalid provider environment fields: %s", ", ".join(sorted(invalid)))


def initial_provider_config(legacy: dict) -> dict:
    config = normalize_provider_config({**provider_config_from_environment(), **legacy})
    if not config.get("IMAGE_PROVIDER") and not config.get("DISABLE_IMAGE_GENERATION"):
        if all(config.get(key) for key in ("OPENAI_COMPAT_IMAGE_BASE_URL", "OPENAI_COMPAT_IMAGE_API_KEY", "OPENAI_COMPAT_IMAGE_MODEL")):
            config["IMAGE_PROVIDER"] = "openai_compatible"
        elif config.get("OPEN_WEBUI_IMAGE_URL"):
            config["IMAGE_PROVIDER"] = "open_webui"
        elif config.get("COMFYUI_URL"):
            config["IMAGE_PROVIDER"] = "comfyui"
        elif config.get("PEXELS_API_KEY"):
            config["IMAGE_PROVIDER"] = "pexels"
        elif config.get("PIXABAY_API_KEY"):
            config["IMAGE_PROVIDER"] = "pixabay"
        elif config.get("LLM") == "openai" and config.get("OPENAI_API_KEY"):
            config["IMAGE_PROVIDER"] = "gpt-image-1.5"
        elif config.get("LLM") == "google" and config.get("GOOGLE_API_KEY"):
            config["IMAGE_PROVIDER"] = "gemini_flash"
        else:
            config.setdefault("DISABLE_IMAGE_GENERATION", True)
    return config


def update_env_with_provider_config(config: dict) -> None:
    """Project DB values, including removals, for existing provider clients."""
    normalized = UserConfig.model_validate(config).model_dump()
    for key, value in normalized.items():
        # A deployment-level telemetry opt-out always remains effective.
        if key == "DISABLE_ANONYMOUS_TRACKING":
            continue
        if value is None:
            os.environ.pop(key, None)
        elif isinstance(value, list):
            os.environ[key] = ",".join(value)
        else:
            os.environ[key] = str(value)


def save_codex_tokens_to_database(*, include_model: bool = False) -> None:
    """Persist only OAuth-managed fields directly in the database.

    Called by synchronous provider integrations after refresh or logout.
    """
    from services.provider_settings import CODEX_MANAGED_FIELDS, patch_provider_settings_sync
    keys = CODEX_MANAGED_FIELDS | ({"CODEX_MODEL"} if include_model else set())
    patch_provider_settings_sync(normalize_provider_config({key: os.getenv(key) for key in keys}))
