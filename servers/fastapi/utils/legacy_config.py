"""Read-only import of configuration from installations predating DB settings."""
import os

from utils.get_env import get_app_data_directory_env, get_user_config_path_env
from utils.user_config_store import read_user_config_file


def read_legacy_config() -> dict:
    path = get_user_config_path_env()
    if not path:
        directory = get_app_data_directory_env()
        path = os.path.join(directory, "userConfig.json") if directory else None
    return read_user_config_file(path, strict=True) if path else {}
