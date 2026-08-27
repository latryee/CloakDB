"""Configuration loader with environment variable interpolation and YAML/JSON support."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from cloakdb.config.models import CloakConfig

_ENV_VAR_PATTERN = re.compile(r"\$\{([A-Za-z0-9_]+)(?::([^}]*))?\}")


def _interpolate_env_vars(data: Any) -> Any:
    """Recursively interpolates environment variables in the format ${VAR} or ${VAR:default}."""
    if isinstance(data, str):

        def _replace(match: re.Match[str]) -> str:
            var_name = match.group(1)
            default_val = match.group(2) if match.group(2) is not None else ""
            return os.environ.get(var_name, default_val)

        return _ENV_VAR_PATTERN.sub(_replace, data)
    elif isinstance(data, dict):
        return {k: _interpolate_env_vars(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [_interpolate_env_vars(item) for item in data]
    return data


def load_config(config_path: str | Path) -> CloakConfig:
    """Loads and validates a CloakDB YAML or JSON configuration file."""
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    raw_text = path.read_text(encoding="utf-8")
    try:
        raw_data = yaml.safe_load(raw_text) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"Failed to parse YAML configuration: {exc}") from exc

    interpolated_data = _interpolate_env_vars(raw_data)

    try:
        return CloakConfig.model_validate(interpolated_data)
    except ValidationError as exc:
        errors = []
        for err in exc.errors():
            loc = " -> ".join(str(p) for p in err.get("loc", []))
            msg = err.get("msg", "")
            errors.append(f"  • [{loc}]: {msg}")
        joined = "\n".join(errors)
        raise ValueError(f"Invalid CloakDB configuration in '{path}':\n{joined}") from exc


def dump_config_to_yaml(config: CloakConfig) -> str:
    """Converts a CloakConfig instance into cleanly formatted YAML."""
    raw_dict = config.model_dump(by_alias=True, exclude_none=True)
    return yaml.dump(raw_dict, sort_keys=False, default_flow_style=False, allow_unicode=True)


def save_config(config: CloakConfig, output_path: str | Path) -> None:
    """Saves a CloakConfig instance to a YAML file."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    yaml_content = dump_config_to_yaml(config)
    path.write_text(yaml_content, encoding="utf-8")
