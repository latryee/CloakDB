"""CLI end-to-end integration tests."""

from pathlib import Path
from typer.testing import CliRunner
from cloakdb.cli import app

runner = CliRunner()


def test_cli_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "CloakDB" in result.stdout


def test_cli_strategies():
    result = runner.invoke(app, ["strategies"])
    assert result.exit_code == 0
    assert "deterministic_hash" in result.stdout
    assert "faker" in result.stdout


def test_cli_init_and_scan(tmp_path: Path, postgres_dump_file: Path):
    # Test init
    config_file = tmp_path / "cloakdb.yaml"
    res_init = runner.invoke(app, ["init", "-o", str(config_file)])
    assert res_init.exit_code == 0
    assert config_file.exists()

    # Test scan
    res_scan = runner.invoke(app, ["scan", str(postgres_dump_file)])
    assert res_scan.exit_code == 0
    assert "users" in res_scan.stdout


def test_cli_apply(tmp_path: Path, postgres_dump_file: Path):
    config_file = tmp_path / "cloakdb.yaml"
    runner.invoke(app, ["init", "-o", str(config_file)])

    out_dump = tmp_path / "masked.sql"
    res_apply = runner.invoke(app, ["apply", "-c", str(config_file), "-i", str(postgres_dump_file), "-o", str(out_dump)])
    assert res_apply.exit_code == 0
    assert out_dump.exists()
    assert "Completed Successfully" in res_apply.stdout
