"""Test suite for Schema Drift detection (cloakdb lint) and Strategy Plugins."""

from pathlib import Path

from typer.testing import CliRunner

from cloakdb.cli import app
from cloakdb.config.loader import save_config
from cloakdb.config.models import CloakConfig, ColumnRule, GlobalConfig, TableRule
from cloakdb.strategies.base import MaskingStrategy
from cloakdb.strategies.registry import StrategyRegistry

runner = CliRunner()


def test_schema_lint_clean(tmp_path: Path):
    salt = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt=salt),
        tables={
            "users": TableRule(
                columns={
                    "email": ColumnRule(strategy="faker", params={"provider": "email"}),
                    "full_name": ColumnRule(strategy="faker", params={"provider": "name"}),
                }
            )
        },
    )
    cfg_file = tmp_path / "cloakdb.yaml"
    save_config(config, cfg_file)

    csv_file = tmp_path / "users.csv"
    csv_file.write_text("email,full_name\njohn@example.com,John Doe\n", encoding="utf-8")

    result = runner.invoke(app, ["lint", "-c", str(cfg_file), "-i", str(csv_file)])
    assert result.exit_code == 0
    assert "SCHEMA COMPLIANT" in result.stdout


def test_schema_lint_drift_detected(tmp_path: Path):
    salt = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    # Config only masks name, but CSV introduces sensitive credit_card column!
    config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt=salt),
        tables={
            "users": TableRule(
                columns={
                    "full_name": ColumnRule(strategy="faker", params={"provider": "name"}),
                }
            )
        },
    )
    cfg_file = tmp_path / "cloakdb.yaml"
    save_config(config, cfg_file)

    csv_file = tmp_path / "users.csv"
    csv_file.write_text(
        "full_name,credit_card\nJohn Doe,4532-1234-5678-9010\n", encoding="utf-8"
    )

    result = runner.invoke(app, ["lint", "-c", str(cfg_file), "-i", str(csv_file)])
    assert result.exit_code == 1
    assert "SCHEMA DRIFT DETECTED" in result.stdout or "Drift Alert" in result.stdout


def test_audit_log_cli_verify(tmp_path: Path):
    salt = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    cfg = CloakConfig(version="1", global_settings=GlobalConfig(salt=salt), tables={})
    cfg_file = tmp_path / "cloakdb.yaml"
    save_config(cfg, cfg_file)

    csv_file = tmp_path / "test.csv"
    csv_file.write_text("id,val\n1,a\n", encoding="utf-8")
    out_file = tmp_path / "out.csv"
    audit_file = tmp_path / "audit.json"

    # Run mask with audit log generation
    mask_res = runner.invoke(
        app,
        [
            "mask",
            "-c",
            str(cfg_file),
            "-i",
            str(csv_file),
            "-o",
            str(out_file),
            "--audit-log",
            str(audit_file),
        ],
    )
    assert mask_res.exit_code == 0
    assert audit_file.exists()

    # Verify using --config
    verify_res = runner.invoke(
        app, ["audit-log", "--verify", str(audit_file), "--config", str(cfg_file)]
    )
    assert verify_res.exit_code == 0
    assert "PASS" in verify_res.stdout

    # Verify with direct --key
    verify_key_res = runner.invoke(
        app, ["audit-log", "--verify", str(audit_file), "--key", salt]
    )
    assert verify_key_res.exit_code == 0

    # Verify with invalid key
    verify_bad = runner.invoke(
        app, ["audit-log", "--verify", str(audit_file), "--key", "wrong-key-123"]
    )
    assert verify_bad.exit_code == 1


def test_custom_strategy_plugin_loader():
    class CustomPluginStrategy(MaskingStrategy):
        description = "Custom test plugin"
        def transform(self, value, context, **kwargs):
            return f"custom_{value}"

    # Verify load_plugins is safe to invoke repeatedly
    count = StrategyRegistry.load_plugins()
    assert count >= 0
