"""Unit and integration tests for CloakDB Security Hardening features."""

from __future__ import annotations

import secrets
from pathlib import Path

from typer.testing import CliRunner

from cloakdb.cli import app
from cloakdb.config.loader import save_config
from cloakdb.config.models import CloakConfig, ColumnRule, GlobalConfig, TableRule
from cloakdb.core.engine import CloakEngine
from cloakdb.utils.security import (
    compute_salt_fingerprint,
    is_insecure_salt,
    is_production_connection,
)

runner = CliRunner()


def test_is_insecure_salt_rules():
    """Verify default and weak salt heuristics."""
    is_weak, _ = is_insecure_salt("cloakdb-salt")
    assert is_weak is True

    is_weak, _ = is_insecure_salt("default")
    assert is_weak is True

    is_weak, _ = is_insecure_salt("short_salt_123")
    assert is_weak is True

    is_weak, _ = is_insecure_salt("")
    assert is_weak is True

    is_weak, _ = is_insecure_salt(None)
    assert is_weak is True

    # 32+ character random hex salt is secure
    secure_salt = secrets.token_hex(32)
    is_weak, reason = is_insecure_salt(secure_salt)
    assert is_weak is False
    assert reason == ""


def test_salt_fingerprint_generation_and_verification():
    """Verify SHA-256 fingerprint generation and mismatch detection."""
    salt_a = secrets.token_hex(32)
    fp_a = compute_salt_fingerprint(salt_a)
    assert len(fp_a) == 16

    salt_b = secrets.token_hex(32)
    fp_b = compute_salt_fingerprint(salt_b)
    assert fp_a != fp_b

    config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(
            salt=salt_a,
            salt_fingerprint=fp_a,
        ),
    )
    assert config.global_settings.verify_fingerprint() is True

    # Rotate salt without updating fingerprint
    config.global_settings.salt = salt_b
    assert config.global_settings.verify_fingerprint() is False


def test_is_production_connection_heuristics():
    """Verify production database URL detection."""
    assert is_production_connection("postgresql://user:pass@prod-db.internal:5432/app") is True
    assert is_production_connection("postgresql://user:pass@localhost:5432/production_app") is True
    assert (
        is_production_connection("mysql://root:pass@live-master.aws.rds.amazonaws.com:3306/db")
        is True
    )
    assert is_production_connection("postgresql://user:pass@localhost:5432/test_db") is False
    assert is_production_connection("sqlite:///local_dev.db") is False
    assert is_production_connection("/path/to/dump.sql") is False


def test_cli_apply_insecure_salt_fails_without_flag(tmp_path: Path):
    """Applying with an insecure/weak salt aborts unless --allow-insecure-salt is given."""
    cfg_file = tmp_path / "insecure_config.yaml"
    in_file = tmp_path / "data.csv"
    out_file = tmp_path / "out.csv"

    in_file.write_text("id,name\n1,Alice\n", encoding="utf-8")

    weak_salt = "weak-short-salt"
    config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt=weak_salt),
        tables={
            "data": TableRule(
                columns={"name": ColumnRule(strategy="constant", params={"value_to_set": "X"})}
            )
        },
    )
    save_config(config, cfg_file)

    # 1. Should fail without --allow-insecure-salt
    result = runner.invoke(
        app,
        ["apply", "-c", str(cfg_file), "-i", str(in_file), "-o", str(out_file)],
    )
    assert result.exit_code == 1
    assert "INSECURE / DEFAULT SALT DETECTED" in result.output

    # 2. Should succeed with --allow-insecure-salt
    result_allowed = runner.invoke(
        app,
        [
            "apply",
            "-c",
            str(cfg_file),
            "-i",
            str(in_file),
            "-o",
            str(out_file),
            "--allow-insecure-salt",
        ],
    )
    assert result_allowed.exit_code == 0
    assert out_file.exists()


def test_cli_apply_salt_fingerprint_mismatch(tmp_path: Path):
    """Applying with a mismatched salt fingerprint aborts unless overridden."""
    cfg_file = tmp_path / "fp_config.yaml"
    in_file = tmp_path / "data.csv"
    out_file = tmp_path / "out.csv"

    in_file.write_text("id,name\n1,Alice\n", encoding="utf-8")

    salt_original = secrets.token_hex(32)
    salt_rotated = secrets.token_hex(32)

    config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(
            salt=salt_rotated,
            salt_fingerprint=compute_salt_fingerprint(salt_original),
        ),
        tables={
            "data": TableRule(
                columns={"name": ColumnRule(strategy="constant", params={"value_to_set": "X"})}
            )
        },
    )
    save_config(config, cfg_file)

    # 1. Fails by default
    result = runner.invoke(
        app,
        ["apply", "-c", str(cfg_file), "-i", str(in_file), "-o", str(out_file)],
    )
    assert result.exit_code == 1
    assert "SALT ROTATION / MISMATCH DETECTED" in result.output

    # 2. Succeeds with --ignore-salt-mismatch
    result_ignored = runner.invoke(
        app,
        [
            "apply",
            "-c",
            str(cfg_file),
            "-i",
            str(in_file),
            "-o",
            str(out_file),
            "--ignore-salt-mismatch",
        ],
    )
    assert result_ignored.exit_code == 0


def test_stateless_deterministic_hash_across_runs_and_memory():
    """Verify stateless mode produces identical deterministic integers without LRU caching."""
    salt = secrets.token_hex(32)
    config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(
            salt=salt,
            stateless=True,
            cache_pseudonyms=False,
        ),
        tables={
            "users": TableRule(
                columns={
                    "user_id": ColumnRule(
                        strategy="deterministic_hash",
                        params={"as_integer": True, "min_int": 1000, "max_int": 99999},
                    )
                }
            )
        },
    )

    engine1 = CloakEngine(config)
    engine2 = CloakEngine(config)

    # ReferentialIntegrityManager cache should be disabled
    assert engine1.integrity_manager.cache_enabled is False

    val_a1 = engine1.mask_record("users", {"user_id": 42})["user_id"]
    val_a2 = engine2.mask_record("users", {"user_id": 42})["user_id"]
    val_b1 = engine1.mask_record("users", {"user_id": 9999})["user_id"]

    assert val_a1 == val_a2
    assert 1000 <= val_a1 <= 99999
    assert val_a1 != val_b1


def test_cli_verify_detects_unmasked_pii_and_passes_clean_output(tmp_path: Path):
    """cloakdb verify reports failure on leaked PII and success on clean masked data."""
    leaked_file = tmp_path / "leaked.csv"
    leaked_file.write_text(
        "id,email,credit_card\n1,john.doe@example.com,4532015018092784\n",
        encoding="utf-8",
    )

    # 1. Verify on unmasked data should FAIL (exit 1)
    res_leaked = runner.invoke(app, ["verify", "-i", str(leaked_file)])
    assert res_leaked.exit_code == 1
    assert "VERIFICATION FAILED" in res_leaked.output

    # 2. Verify on masked data should PASS (exit 0)
    clean_file = tmp_path / "clean.csv"
    clean_file.write_text(
        "id,email,credit_card\n1,a***r@example.com,****-****-****-2784\n",
        encoding="utf-8",
    )
    res_clean = runner.invoke(app, ["verify", "-i", str(clean_file)])
    assert res_clean.exit_code == 0
    assert "ZERO UNMASKED PII DETECTED" in res_clean.output
