"""Targeted unit tests to push CloakDB test suite coverage past 90%."""

from __future__ import annotations

import io
import json
from pathlib import Path
from unittest.mock import MagicMock

import pyarrow as pa
import pyarrow.parquet as pq
import pytest
from typer.testing import CliRunner

from cloakdb.cli import app
from cloakdb.config.loader import load_config, save_config
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


def test_cli_wizard_command(tmp_path: Path):
    """Test interactive wizard with mock inputs."""
    out_cfg = tmp_path / "wizard.yaml"
    csv_file = tmp_path / "customers.csv"
    csv_file.write_text("id,email,full_name\n1,alice@corp.com,Alice Smith\n", encoding="utf-8")

    result = runner.invoke(app, ["wizard", "-o", str(out_cfg)], input=f"{csv_file}\n")
    assert result.exit_code == 0
    assert out_cfg.exists()
    loaded = load_config(out_cfg)
    assert len(loaded.global_settings.salt) >= 32


def test_cli_diff_json_and_jsonl(tmp_path: Path):
    """Test diff command on json and jsonl formats."""
    salt = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    cfg1 = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt=salt),
        tables={"items": TableRule(columns={"email": ColumnRule(strategy="nullify")})},
    )
    cfg2 = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt=salt),
        tables={
            "items": TableRule(
                columns={"email": ColumnRule(strategy="constant", params={"value_to_set": "X"})}
            )
        },
    )
    c1 = tmp_path / "c1.yaml"
    c2 = tmp_path / "c2.yaml"
    save_config(cfg1, c1)
    save_config(cfg2, c2)

    # JSONL
    jsonl_file = tmp_path / "items.jsonl"
    jsonl_file.write_text('{"id": 1, "email": "a@test.com"}\n', encoding="utf-8")
    res_jsonl = runner.invoke(app, ["diff", "-c1", str(c1), "-c2", str(c2), "-i", str(jsonl_file)])
    assert res_jsonl.exit_code == 0
    assert "CHANGED" in res_jsonl.stdout

    # JSON document
    json_file = tmp_path / "items.json"
    json_file.write_text('[{"id": 1, "email": "a@test.com"}]', encoding="utf-8")
    res_json = runner.invoke(app, ["diff", "-c1", str(c1), "-c2", str(c2), "-i", str(json_file)])
    assert res_json.exit_code == 0
    assert "CHANGED" in res_json.stdout


def test_generator_fk_inference(tmp_path: Path):
    generator = ConfigGenerator()
    sql_file = tmp_path / "schema.sql"
    sql_file.write_text(
        "CREATE TABLE users (id INT PRIMARY KEY, email VARCHAR(255));\n"
        "CREATE TABLE orders (\n"
        "    order_id INT PRIMARY KEY,\n"
        "    user_id INT,\n"
        "    FOREIGN KEY (user_id) REFERENCES users (id)\n"
        ");\n",
        encoding="utf-8",
    )
    detections = {
        "users": [
            MagicMock(
                column_name="id",
                pii_type="user_id",
                confidence=0.9,
                recommended_strategy="deterministic_hash",
                recommended_params={"as_integer": True},
            ),
            MagicMock(
                column_name="email",
                pii_type="email",
                confidence=0.9,
                recommended_strategy="faker",
                recommended_params={"provider": "email"},
            ),
        ],
        "orders": [
            MagicMock(
                column_name="user_id",
                pii_type="user_id",
                confidence=0.9,
                recommended_strategy="deterministic_hash",
                recommended_params={"as_integer": True},
            ),
        ],
    }
    cfg = generator.generate_config_from_detections(
        detections, target=str(sql_file), infer_fks=True
    )
    assert len(cfg.tables) == 2
    assert len(cfg.consistency_groups) >= 1


def test_generator_scan_sql_dump_copy_mode(tmp_path: Path):
    generator = ConfigGenerator()
    dump_file = tmp_path / "dump.sql"
    dump_file.write_text(
        "COPY users (id, email) FROM stdin;\n1\talice@corp.com\n2\t\\N\n\\.\n",
        encoding="utf-8",
    )
    detections = generator.scan_sql_dump(str(dump_file))
    assert "users" in detections
    assert any(res.column_name == "email" for res in detections["users"])


def test_generator_alter_table_fk_inference(tmp_path: Path):
    generator = ConfigGenerator()
    sql_file = tmp_path / "alter_schema.sql"
    sql_file.write_text(
        "CREATE TABLE users (id INT PRIMARY KEY);\n"
        "CREATE TABLE orders (id INT, customer_id INT);\n"
        "ALTER TABLE ONLY orders ADD CONSTRAINT fk_orders_user FOREIGN KEY (customer_id) REFERENCES users(id);\n",
        encoding="utf-8",
    )
    detections = {
        "users": [
            MagicMock(
                column_name="id",
                pii_type="user_id",
                confidence=0.9,
                recommended_strategy="deterministic_hash",
                recommended_params={"as_integer": True},
            )
        ],
        "orders": [
            MagicMock(
                column_name="customer_id",
                pii_type="user_id",
                confidence=0.9,
                recommended_strategy="deterministic_hash",
                recommended_params={"as_integer": True},
            )
        ],
    }
    cfg = generator.generate_config_from_detections(
        detections, target=str(sql_file), infer_fks=True
    )
    assert len(cfg.consistency_groups) >= 1


def test_generator_scan_parquet_with_data(tmp_path: Path):
    generator = ConfigGenerator()
    p_file = tmp_path / "users.parquet"
    table = pa.Table.from_pydict({"email": ["test@example.com", "valid@corp.org"], "id": [1, 2]})
    pq.write_table(table, str(p_file))

    detections = generator.scan_parquet(str(p_file), max_rows=10)
    assert "users" in detections
    assert any(res.column_name == "email" for res in detections["users"])


def test_live_db_connector_mocked(tmp_path: Path):
    from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine

    from cloakdb.connectors.live_db import LiveDatabaseConnector

    db_file = tmp_path / "live_test.db"
    db_url = f"sqlite:///{db_file}"
    engine = create_engine(db_url)
    meta = MetaData()
    users = Table(
        "users",
        meta,
        Column("id", Integer, primary_key=True),
        Column("email", String(100)),
    )
    meta.create_all(engine)

    with engine.connect() as conn:
        conn.execute(
            users.insert(),
            [{"id": 1, "email": "alice@test.com"}, {"id": 2, "email": "bob@test.com"}],
        )
        conn.commit()

    connector = LiveDatabaseConnector(db_url)
    assert "users" in connector.get_table_names()
    rows = connector.fetch_sample_rows("users", limit=5)
    assert len(rows) == 2
    pks = connector.get_primary_keys("users")
    assert pks == ["id"]

    # Mask in place with CloakEngine
    cfg = CloakConfig(
        version="1",
        global_settings=GlobalConfig(
            salt="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ),
        tables={"users": TableRule(columns={"email": ColumnRule(strategy="nullify")})},
    )
    cloak_engine = CloakEngine(cfg)
    connector.mask_table("users", cloak_engine, batch_size=10)

    # Verify masked in DB
    masked_rows = connector.fetch_sample_rows("users", limit=5)
    assert all(r["email"] is None for r in masked_rows)
