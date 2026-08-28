"""Tests for interactive configuration wizard and GitHub action.yml specification."""

from __future__ import annotations

from pathlib import Path

import yaml
from typer.testing import CliRunner

from cloakdb.cli import app
from cloakdb.config.loader import load_config

runner = CliRunner()


def test_wizard_command_generates_valid_config(tmp_path: Path):
    """Test interactive wizard generates a valid, strong config file with salt fingerprint."""
    csv_file = tmp_path / "dataset.csv"
    csv_file.write_text("id,full_name,email\n1,Alice,alice@example.com\n", encoding="utf-8")

    out_yaml = tmp_path / "wizard_config.yaml"

    # Feed input path into wizard prompt
    result = runner.invoke(
        app,
        ["wizard", "-o", str(out_yaml), "-l", "en_US"],
        input=f"{csv_file}\n",
    )

    assert result.exit_code == 0
    assert "CloakDB Configuration Wizard" in result.output
    assert "SUCCESS!" in result.output
    assert out_yaml.exists()

    cfg = load_config(out_yaml)
    assert len(cfg.global_settings.salt) >= 32
    assert cfg.global_settings.salt_fingerprint is not None
    assert len(cfg.tables) > 0


def test_action_yaml_specification():
    """Verify root action.yml is valid YAML and defines expected inputs and outputs."""
    action_path = Path(__file__).resolve().parent.parent / "action.yml"
    assert action_path.exists()

    data = yaml.safe_load(action_path.read_text(encoding="utf-8"))
    assert data["name"] == "CloakDB Masking Action"
    assert "inputs" in data
    assert "config" in data["inputs"]
    assert "input" in data["inputs"]
    assert "verify" in data["inputs"]
    assert data["runs"]["using"] == "composite"
