"""Tests for Section 4 features: Incremental masking, Config Diff, and JSON document stream parser."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from cloakdb.cli import app
from cloakdb.config.loader import save_config
from cloakdb.config.models import CloakConfig, ColumnRule, GlobalConfig, TableRule
from cloakdb.core.engine import CloakEngine
from cloakdb.parsers.json_stream import JSONDocumentStreamParser

runner = CliRunner()


def test_incremental_masking_mode():
    """Verify incremental masking only masks rows where timestamp >= since."""
    config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt="test-incremental-salt-1234567890"),
        tables={
            "users": TableRule(
                columns={
                    "email": ColumnRule(
                        strategy="constant", params={"value_to_set": "masked@test.com"}
                    )
                }
            )
        },
    )

    engine = CloakEngine(
        config,
        incremental_since="2026-06-01T00:00:00",
        incremental_column="updated_at",
    )

    old_row = {"id": 1, "email": "alice@old.com", "updated_at": "2026-01-15T12:00:00"}
    new_row = {"id": 2, "email": "bob@new.com", "updated_at": "2026-07-20T10:00:00"}

    masked_old = engine.mask_record("users", old_row)
    masked_new = engine.mask_record("users", new_row)

    # Old row must remain unchanged
    assert masked_old["email"] == "alice@old.com"
    # New row must be masked
    assert masked_new["email"] == "masked@test.com"


def test_json_document_stream_parser(tmp_path: Path):
    """Verify JSONDocumentStreamParser correctly masks JSON array files."""
    config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt="test-json-salt-1234567890123456"),
        tables={
            "users": TableRule(
                columns={
                    "full_name": ColumnRule(
                        strategy="constant", params={"value_to_set": "Anonymous"}
                    )
                }
            )
        },
    )
    engine = CloakEngine(config)

    in_json = tmp_path / "dataset.json"
    out_json = tmp_path / "masked_dataset.json"

    data = [
        {"id": 1, "full_name": "Alice Wonderland", "email": "alice@domain.com"},
        {"id": 2, "full_name": "Bob Builder", "email": "bob@domain.com"},
    ]
    in_json.write_text(json.dumps(data), encoding="utf-8")

    parser = JSONDocumentStreamParser(table_name="users")
    with in_json.open("r", encoding="utf-8") as in_f:
        with out_json.open("w", encoding="utf-8") as out_f:
            parser.process_stream(in_f, out_f, engine)

    result_data = json.loads(out_json.read_text(encoding="utf-8"))
    assert len(result_data) == 2
    assert result_data[0]["full_name"] == "Anonymous"
    assert result_data[1]["full_name"] == "Anonymous"
    assert result_data[0]["email"] == "alice@domain.com"


def test_cli_diff_command(tmp_path: Path):
    """Verify cloakdb diff compares outputs between two config files."""
    cfg1_path = tmp_path / "cfg1.yaml"
    cfg2_path = tmp_path / "cfg2.yaml"
    data_path = tmp_path / "sample.csv"

    data_path.write_text(
        "id,name,email\n1,Alice,alice@example.com\n2,Bob,bob@example.com\n", encoding="utf-8"
    )

    cfg1 = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt="0123456789abcdef0123456789abcdef"),
        tables={
            "default": TableRule(
                columns={
                    "name": ColumnRule(strategy="constant", params={"value_to_set": "MASKED_1"})
                }
            )
        },
    )
    cfg2 = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt="0123456789abcdef0123456789abcdef"),
        tables={
            "default": TableRule(
                columns={
                    "name": ColumnRule(strategy="constant", params={"value_to_set": "MASKED_2"})
                }
            )
        },
    )

    save_config(cfg1, cfg1_path)
    save_config(cfg2, cfg2_path)

    res = runner.invoke(
        app,
        ["diff", "-c1", str(cfg1_path), "-c2", str(cfg2_path), "-i", str(data_path), "-n", "2"],
    )

    assert res.exit_code == 0
    assert "Side-by-Side Masking Output Diff" in res.output
    assert "MASKED_1" in res.output
    assert "MASKED_2" in res.output
    assert "CHANGED" in res.output
