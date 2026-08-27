"""CLI end-to-end integration tests."""

import json
from pathlib import Path

from typer.testing import CliRunner

from cloakdb.cli import app

runner = CliRunner()


def test_cli_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "CloakDB" in result.stdout


def test_cli_version_flag():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "CloakDB" in result.stdout


def test_cli_strategies():
    result = runner.invoke(app, ["strategies"])
    assert result.exit_code == 0
    assert "deterministic_hash" in result.stdout
    assert "faker" in result.stdout


def test_cli_bench():
    result = runner.invoke(app, ["bench", "--rows", "1000"])
    assert result.exit_code == 0
    assert "Benchmark Results" in result.stdout
    assert "1,000" in result.stdout


def test_cli_init_and_scan(tmp_path: Path, postgres_dump_file: Path):
    config_file = tmp_path / "cloakdb.yaml"
    res_init = runner.invoke(app, ["init", "-o", str(config_file)])
    assert res_init.exit_code == 0
    assert config_file.exists()

    # Re-init without force should fail
    res_init_fail = runner.invoke(app, ["init", "-o", str(config_file)])
    assert res_init_fail.exit_code == 1
    assert "already exists" in res_init_fail.output

    # Re-init with force should succeed
    res_init_force = runner.invoke(app, ["init", "-o", str(config_file), "--force"])
    assert res_init_force.exit_code == 0

    # Test scan
    res_scan = runner.invoke(app, ["scan", str(postgres_dump_file)])
    assert res_scan.exit_code == 0
    assert "users" in res_scan.stdout


def test_cli_preview_sql(tmp_path: Path, postgres_dump_file: Path):
    config_file = tmp_path / "cloakdb.yaml"
    runner.invoke(app, ["init", "-o", str(config_file)])

    res_preview = runner.invoke(
        app, ["preview", "-c", str(config_file), "-i", str(postgres_dump_file), "-n", "2"]
    )
    assert res_preview.exit_code == 0
    assert "Preview" in res_preview.stdout


def test_cli_preview_csv(tmp_path: Path, csv_file: Path):
    config_file = tmp_path / "cloakdb.yaml"
    runner.invoke(app, ["init", "-o", str(config_file)])

    res_preview = runner.invoke(
        app, ["preview", "-c", str(config_file), "-i", str(csv_file), "-n", "2"]
    )
    assert res_preview.exit_code == 0
    assert "CSV Preview" in res_preview.stdout


def test_cli_apply_sql(tmp_path: Path, postgres_dump_file: Path):
    config_file = tmp_path / "cloakdb.yaml"
    runner.invoke(app, ["init", "-o", str(config_file)])

    out_dump = tmp_path / "masked.sql"
    res_apply = runner.invoke(
        app, ["apply", "-c", str(config_file), "-i", str(postgres_dump_file), "-o", str(out_dump)]
    )
    assert res_apply.exit_code == 0
    assert out_dump.exists()
    assert "Completed Successfully" in res_apply.stdout


def test_cli_apply_dry_run(tmp_path: Path, postgres_dump_file: Path):
    config_file = tmp_path / "cloakdb.yaml"
    runner.invoke(app, ["init", "-o", str(config_file)])

    res_dry = runner.invoke(
        app, ["apply", "-c", str(config_file), "-i", str(postgres_dump_file), "--dry-run"]
    )
    assert res_dry.exit_code == 0
    assert "Completed Successfully" in res_dry.stdout


def test_cli_apply_csv(tmp_path: Path, csv_file: Path):
    config_file = tmp_path / "cloakdb.yaml"
    runner.invoke(app, ["init", "-o", str(config_file)])

    out_csv = tmp_path / "masked.csv"
    res = runner.invoke(
        app, ["apply", "-c", str(config_file), "-i", str(csv_file), "-o", str(out_csv)]
    )
    assert res.exit_code == 0
    assert out_csv.exists()
    content = out_csv.read_text(encoding="utf-8")
    assert "id,email,full_name,salary,phone" in content
    assert "john.doe@example.com" not in content


def test_cli_apply_jsonl(tmp_path: Path):
    jsonl_in = tmp_path / "users.jsonl"
    data = [
        {"id": 1, "email": "user1@example.com", "full_name": "User One"},
        {"id": 2, "email": "user2@example.com", "full_name": "User Two"},
    ]
    with jsonl_in.open("w", encoding="utf-8") as f:
        for d in data:
            f.write(json.dumps(d) + "\n")

    config_file = tmp_path / "cloakdb.yaml"
    runner.invoke(app, ["init", "-o", str(config_file)])

    jsonl_out = tmp_path / "masked.jsonl"
    res = runner.invoke(
        app, ["apply", "-c", str(config_file), "-i", str(jsonl_in), "-o", str(jsonl_out)]
    )
    assert res.exit_code == 0
    assert jsonl_out.exists()
    content = jsonl_out.read_text(encoding="utf-8")
    assert "user1@example.com" not in content


def test_cli_apply_missing_file_errors(tmp_path: Path):
    config_file = tmp_path / "cloakdb.yaml"
    runner.invoke(app, ["init", "-o", str(config_file)])

    # Nonexistent input file
    res = runner.invoke(
        app,
        [
            "apply",
            "-c",
            str(config_file),
            "-i",
            "nonexistent_file.sql",
            "-o",
            str(tmp_path / "out.sql"),
        ],
    )
    assert res.exit_code == 1
    assert "does not exist" in res.output

    # Missing output when not in dry-run
    sql_file = tmp_path / "dummy.sql"
    sql_file.write_text("SELECT 1;", encoding="utf-8")
    res_no_out = runner.invoke(app, ["apply", "-c", str(config_file), "-i", str(sql_file)])
    assert res_no_out.exit_code == 1
    assert "Output path" in res_no_out.output
