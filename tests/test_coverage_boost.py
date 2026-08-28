"""Targeted unit tests to push CloakDB test suite coverage past 90%."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pytest
from typer.testing import CliRunner

from cloakdb.cli import app
from cloakdb.config.loader import save_config
from cloakdb.config.models import CloakConfig, ColumnRule, GlobalConfig, TableRule
from cloakdb.core.context import TransformationContext
from cloakdb.core.engine import CloakEngine
from cloakdb.parsers.json_stream import JSONDocumentStreamParser
from cloakdb.parsers.parquet_stream import ParquetStreamParser
from cloakdb.scanner.generator import ConfigGenerator
from cloakdb.strategies.differential_privacy import DifferentialPrivacyStrategy

runner = CliRunner()


def test_parquet_process_stream_in_memory():
    """Verify ParquetStreamParser.process_stream works directly on memory buffers."""
    config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt="0123456789abcdef0123456789abcdef"),
        tables={
            "users": TableRule(
                columns={
                    "email": ColumnRule(
                        strategy="constant", params={"value_to_set": "masked@corp.com"}
                    )
                }
            )
        },
    )
    engine = CloakEngine(config)
    parser = ParquetStreamParser(table_name="users", batch_size=10)

    # Create parquet in-memory
    table = pa.Table.from_pydict(
        {"id": [1, 2, 3], "email": ["a@corp.com", "b@corp.com", "c@corp.com"]}
    )
    in_buf = io.BytesIO()
    pq.write_table(table, in_buf)
    in_buf.seek(0)

    out_buf = io.StringIO()
    progress_called = False

    def on_prog(r: int, b: int) -> None:
        nonlocal progress_called
        progress_called = True

    parser.process_stream(in_buf, out_buf, engine, progress_callback=on_prog)

    assert progress_called is True
    out_raw = out_buf.getvalue().encode("latin1")
    out_table = pq.read_table(io.BytesIO(out_raw))
    assert out_table.num_rows == 3
    assert all(e == "masked@corp.com" for e in out_table.column("email").to_pylist())


def test_cli_version_command():
    """Test cloakdb version prints version and platform."""
    res = runner.invoke(app, ["version"])
    assert res.exit_code == 0
    assert "CloakDB version" in res.output
    assert "Python" in res.output


def test_cli_apply_and_verify_parquet(tmp_path: Path):
    """Test CLI apply and verify end-to-end on .parquet files."""
    in_parquet = tmp_path / "data.parquet"
    out_parquet = tmp_path / "out.parquet"
    cfg_path = tmp_path / "config.yaml"

    table = pa.Table.from_pydict({"id": [1, 2], "email": ["test1@corp.com", "test2@corp.com"]})
    pq.write_table(table, str(in_parquet))

    cfg = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt="0123456789abcdef0123456789abcdef"),
        tables={
            "data": TableRule(
                columns={
                    "email": ColumnRule(strategy="constant", params={"value_to_set": "[REDACTED]"})
                }
            )
        },
    )
    save_config(cfg, cfg_path)

    # Dry-run apply
    dry_res = runner.invoke(app, ["apply", "-c", str(cfg_path), "-i", str(in_parquet), "--dry-run"])
    assert dry_res.exit_code == 0

    # Real apply
    apply_res = runner.invoke(
        app, ["apply", "-c", str(cfg_path), "-i", str(in_parquet), "-o", str(out_parquet)]
    )
    assert apply_res.exit_code == 0
    assert out_parquet.exists()

    # Verify masked output
    verify_res = runner.invoke(app, ["verify", "-i", str(out_parquet)])
    assert verify_res.exit_code == 0
    assert "ZERO UNMASKED PII DETECTED" in verify_res.output


def test_json_document_parser_single_dict_and_malformed(tmp_path: Path):
    """Test JSONDocumentStreamParser handling single JSON objects and empty inputs."""
    config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt="0123456789abcdef0123456789abcdef"),
        tables={
            "doc": TableRule(
                columns={
                    "name": ColumnRule(strategy="constant", params={"value_to_set": "Anonymous"})
                }
            )
        },
    )
    engine = CloakEngine(config)
    parser = JSONDocumentStreamParser(table_name="doc")

    # Single dictionary
    in_stream = io.StringIO('{"id": 1, "name": "Alice"}')
    out_stream = io.StringIO()
    parser.process_stream(in_stream, out_stream, engine)
    assert '"name": "Anonymous"' in out_stream.getvalue()

    # Empty array
    in_empty = io.StringIO("[]")
    out_empty = io.StringIO()
    parser.process_stream(in_empty, out_empty, engine)
    assert json.loads(out_empty.getvalue()) == []

    # Malformed JSON raises ValueError
    in_invalid = io.StringIO('{"id": 1, invalid}')
    with pytest.raises(ValueError, match="Invalid JSON document payload"):
        parser.process_stream(in_invalid, io.StringIO(), engine)


def test_dp_stochastic_and_unbounded():
    """Test DifferentialPrivacyStrategy with deterministic=False and unbounded values."""
    strat = DifferentialPrivacyStrategy()
    ctx = TransformationContext(
        table_name="t", column_name="c", row_index=0, salt="test-salt-1234567890123456"
    )

    # Non-numeric input returns value as-is
    assert strat.transform("not_a_number", ctx) == "not_a_number"

    # Stochastic generation (deterministic=False)
    res = strat.transform(100.0, ctx, deterministic=False, epsilon=2.0)
    assert isinstance(res, float)


def test_scan_parquet_missing_file_handling():
    """Verify scan_parquet handles invalid file paths appropriately."""
    generator = ConfigGenerator()
    with pytest.raises(FileNotFoundError):
        generator.scan_parquet("non_existent_file_path.parquet")
