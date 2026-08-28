"""Unit tests for configuration loader and environment variable interpolation."""

import os
from pathlib import Path

import pytest

from cloakdb.config.loader import (
    _interpolate_env_vars,
    load_config,
    save_config,
)
from cloakdb.config.models import CloakConfig, ColumnRule, GlobalConfig, TableRule


def test_env_var_interpolation():
    os.environ["CLOAK_TEST_SECRET"] = "my_custom_secret"
    data = {
        "salt": "${CLOAK_TEST_SECRET:default_salt}",
        "fallback": "${NON_EXISTENT_VAR:fallback_val}",
        "nested": {"key": "${CLOAK_TEST_SECRET}"},
        "list_items": ["${CLOAK_TEST_SECRET}", 123],
    }

    interpolated = _interpolate_env_vars(data)
    assert interpolated["salt"] == "my_custom_secret"
    assert interpolated["fallback"] == "fallback_val"
    assert interpolated["nested"]["key"] == "my_custom_secret"
    assert interpolated["list_items"][0] == "my_custom_secret"
    assert interpolated["list_items"][1] == 123


def test_load_config_nonexistent(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        load_config(tmp_path / "does_not_exist.yaml")


def test_load_config_invalid_yaml(tmp_path: Path):
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("tables: [unclosed list", encoding="utf-8")
    with pytest.raises(ValueError, match="Failed to parse YAML"):
        load_config(bad_yaml)


def test_load_config_validation_error(tmp_path: Path):
    invalid_config = tmp_path / "invalid.yaml"
    invalid_config.write_text("tables: 'not_a_dictionary'", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid CloakDB configuration"):
        load_config(invalid_config)


def test_load_config_missing_salt_raises_error(tmp_path: Path):
    config_file = tmp_path / "no_salt.yaml"
    config_file.write_text(
        "version: '1'\ntables:\n  users:\n    columns:\n      email:\n        strategy: faker\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Global salt is not set"):
        load_config(config_file)


def test_load_config_empty_salt_raises_error(tmp_path: Path):
    config_file = tmp_path / "empty_salt.yaml"
    config_file.write_text(
        "version: '1'\nglobal:\n  salt: '   '\ntables:\n  users:\n    columns:\n      email:\n        strategy: faker\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Global salt is not set"):
        load_config(config_file)


def test_load_config_valid_salt_succeeds(tmp_path: Path):
    config_file = tmp_path / "valid_salt.yaml"
    config_file.write_text(
        "version: '1'\nglobal:\n  salt: 'abcdef1234567890abcdef1234567890'\ntables:\n  users:\n    columns:\n      email:\n        strategy: faker\n",
        encoding="utf-8",
    )
    loaded = load_config(config_file)
    assert loaded.global_settings.salt == "abcdef1234567890abcdef1234567890"


def test_save_and_load_config_roundtrip(tmp_path: Path):
    config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt="roundtrip-salt-12345678901234567890"),
        tables={
            "users": TableRule(
                columns={"email": ColumnRule(strategy="faker", params={"provider": "email"})}
            )
        },
    )

    out_file = tmp_path / "exported.yaml"
    save_config(config, out_file)
    assert out_file.exists()

    loaded = load_config(out_file)
    assert loaded.global_settings.salt == "roundtrip-salt-12345678901234567890"
    assert "users" in loaded.tables
    assert "email" in loaded.tables["users"].columns
    assert loaded.tables["users"].columns["email"].strategy == "faker"
