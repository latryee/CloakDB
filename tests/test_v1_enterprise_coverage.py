"""Comprehensive test suite targeting maximum branch coverage for CloakDB v1.0.0."""

import json
import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer
from typer.testing import CliRunner

from cloakdb.cli import (
    _check_production_safety,
    _check_salt_fingerprint,
    _check_salt_security,
    app,
)
from cloakdb.config.loader import load_config, save_config
from cloakdb.config.models import CloakConfig, ColumnRule, ConsistencyGroup, GlobalConfig, TableRule
from cloakdb.core.context import TransformationContext
from cloakdb.core.engine import CloakEngine, evaluate_condition
from cloakdb.core.integrity import LRUCache, ReferentialIntegrityManager
from cloakdb.observability.telemetry import (
    CloakTelemetry,
    JSONFormatter,
    _NullSpan,
    setup_structured_logging,
)
from cloakdb.parsers.sql_dump import (
    _clean_identifier,
    _format_sql_value,
    _parse_column_list,
    _parse_sql_value,
    _split_multiple_tuples,
)
from cloakdb.scanner.generator import ConfigGenerator
from cloakdb.strategies.json import JSONMaskStrategy
from cloakdb.strategies.registry import StrategyRegistry
from cloakdb.utils.logger import setup_logging
from cloakdb.utils.security import (
    zeroize_memory,
)

runner = CliRunner()


def test_cli_security_checks(tmp_path: Path):
    # Weak salt check
    with pytest.raises(typer.Exit):
        _check_salt_security("default", allow_insecure_salt=False)
    _check_salt_security("default", allow_insecure_salt=True)
    _check_salt_security("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

    # Production safety check
    with pytest.raises(typer.Exit):
        _check_production_safety("postgresql://user:pass@prod-db.internal:5432/main", confirm_production=False)
    _check_production_safety("postgresql://user:pass@prod-db.internal:5432/main", confirm_production=True)
    _check_production_safety("sqlite:///local.db", confirm_production=False)

    # Salt mismatch check
    cfg = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", salt_fingerprint="mismatch_fp"),
        tables={},
    )
    cfg_file = tmp_path / "cfg.yaml"
    save_config(cfg, cfg_file)

    # Fails when mismatch
    with pytest.raises(typer.Exit):
        _check_salt_fingerprint(cfg, ignore_salt_mismatch=False, update_salt_fingerprint=False)

    # Update fingerprint
    _check_salt_fingerprint(cfg, ignore_salt_mismatch=False, update_salt_fingerprint=True, config_path=cfg_file)
    reloaded = load_config(cfg_file)
    assert reloaded.global_settings.salt_fingerprint == cfg.global_settings.compute_fingerprint()


def test_cli_mask_and_apply_full_options(tmp_path: Path):
    salt = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt=salt, batch_size=100),
        tables={
            "users": TableRule(
                columns={
                    "email": ColumnRule(strategy="nullify"),
                    "score": ColumnRule(strategy="differential_privacy", params={"epsilon": 1.0}),
                }
            )
        },
    )
    cfg_file = tmp_path / "cloakdb.yaml"
    save_config(config, cfg_file)

    sql_file = tmp_path / "input.sql"
    sql_file.write_text(
        "INSERT INTO users (id, email, score) VALUES (1, 'alice@test.com', 95.5);\n",
        encoding="utf-8",
    )
    out_file = tmp_path / "masked.sql"
    audit_file = tmp_path / "audit.json"

    # Test 'mask' command with dry-run, json-logs, stateless, and audit-log
    res_mask = runner.invoke(
        app,
        [
            "mask",
            "-c", str(cfg_file),
            "-i", str(sql_file),
            "-o", str(out_file),
            "--seed", "1234",
            "--locale", "en_US",
            "--stateless",
            "--json-logs",
            "--audit-log", str(audit_file),
        ],
    )
    assert res_mask.exit_code == 0
    assert out_file.exists()
    assert audit_file.exists()

    # Test 'apply' command dry run
    res_apply = runner.invoke(
        app,
        [
            "apply",
            "-c", str(cfg_file),
            "-i", str(sql_file),
            "--dry-run",
        ],
    )
    assert res_apply.exit_code == 0


def test_cli_lint_strict_and_missing_tables(tmp_path: Path):
    salt = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt=salt),
        tables={
            "users": TableRule(columns={"email": ColumnRule(strategy="nullify")}),
            "missing_table": TableRule(columns={"col1": ColumnRule(strategy="nullify")}),
        },
    )
    cfg_file = tmp_path / "cloakdb.yaml"
    save_config(config, cfg_file)

    csv_file = tmp_path / "users.csv"
    csv_file.write_text("email\ntest@example.com\n", encoding="utf-8")

    res_strict = runner.invoke(
        app,
        ["lint", "-c", str(cfg_file), "-i", str(csv_file), "--strict"],
    )
    assert res_strict.exit_code == 1


def test_cli_preview_and_diff(tmp_path: Path):
    salt = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    config1 = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt=salt),
        tables={"users": TableRule(columns={"email": ColumnRule(strategy="nullify")})},
    )
    config2 = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt=salt),
        tables={"users": TableRule(columns={"email": ColumnRule(strategy="constant", params={"value_to_set": "anon@test.com"})})},
    )
    cfg1 = tmp_path / "cfg1.yaml"
    cfg2 = tmp_path / "cfg2.yaml"
    save_config(config1, cfg1)
    save_config(config2, cfg2)

    csv_file = tmp_path / "users.csv"
    csv_file.write_text("email\ntest@example.com\n", encoding="utf-8")

    # Preview CSV
    prev_res = runner.invoke(app, ["preview", "-c", str(cfg1), "-i", str(csv_file), "--limit", "2"])
    assert prev_res.exit_code == 0
    assert "CSV Preview" in prev_res.stdout

    # Diff CSV
    diff_res = runner.invoke(app, ["diff", "-c1", str(cfg1), "-c2", str(cfg2), "-i", str(csv_file)])
    assert diff_res.exit_code == 0
    assert "CHANGED" in diff_res.stdout


def test_cli_audit_log_missing_args():
    res = runner.invoke(app, ["audit-log"])
    assert res.exit_code == 0
    assert "Usage:" in res.stdout

    res_no_key = runner.invoke(app, ["audit-log", "--verify", "dummy.json"])
    assert res_no_key.exit_code == 1


def test_eval_ast_conditions():
    ctx = {"age": 25, "status": "active", "salary": 50000}

    assert evaluate_condition("age > 18 and status == 'active'", ctx) is True
    assert evaluate_condition("age < 18 or salary < 10000", ctx) is False
    assert evaluate_condition("salary >= 50000 and 'act' in status", ctx) is True
    assert evaluate_condition("not (age < 20)", ctx) is True
    assert evaluate_condition("", ctx) is True
    assert evaluate_condition("invalid syntax ???", ctx) is False

    assert evaluate_condition("salary - 10000 > 30000", ctx) is True
    assert evaluate_condition("-age == -25", ctx) is True


def test_lru_cache_and_integrity_manager():
    cache = LRUCache(capacity=2)
    cache.set("k1", "v1")
    cache.set("k2", "v2")
    assert cache.get("k1") == "v1"
    assert cache.contains("k2") is True
    assert cache.get("k3") is None

    cache.set("k3", "v3")
    assert cache.get("k2") is None

    cache.clear()
    assert cache.get("k1") is None

    mgr = ReferentialIntegrityManager(
        groups=[
            ConsistencyGroup(name="user_group", columns=["users.user_id", "orders.customer_id"], strategy="deterministic_hash")
        ]
    )
    grp = mgr.get_group_for_column("users", "user_id")
    assert grp is not None and grp.name == "user_group"
    assert mgr.get_group_for_column("users", "other") is None

    mgr.store_cached_value("user_group", "raw123", "masked456")
    assert mgr.get_cached_value("user_group", "raw123") == "masked456"
    assert mgr.is_collision("user_group", "raw123", "masked456") is False
    assert mgr.is_collision("user_group", "other_raw", "masked456") is True
    assert mgr.get_raw_for_masked("user_group", "masked456") == "raw123"
    assert mgr.get_reverse_lookup("user_group")["masked456"] == "raw123"


def test_null_span_and_json_formatter():
    span = _NullSpan()
    with span as s:
        s.set_attribute("key", "val")
        s.set_status("OK", "description")
        s.record_exception(Exception("error"))

    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="test",
        level=logging.ERROR,
        pathname=__file__,
        lineno=10,
        msg="Sample error",
        args=(),
        exc_info=None,
    )
    record.props = {"ip": "127.0.0.1"}
    formatted = formatter.format(record)
    data = json.loads(formatted)
    assert data["properties"]["ip"] == "127.0.0.1"


def test_sql_parser_helpers():
    assert _clean_identifier("public.users") == "users"
    assert _clean_identifier('"myschema"."customers"') == "customers"
    assert _clean_identifier("[dbo].[orders]") == "orders"

    assert _parse_column_list("id, email, full_name") == ["id", "email", "full_name"]

    assert _parse_sql_value("123.45") == 123.45
    assert _parse_sql_value("1e6") == 1000000.0
    assert _parse_sql_value("100") == 100
    assert _parse_sql_value("N'UnicodeText'") == "UnicodeText"
    assert _parse_sql_value("$$DollarBody$$") == "DollarBody"
    assert _parse_sql_value("plain_raw_symbol") == "plain_raw_symbol"

    assert _format_sql_value(None) == "NULL"
    assert _format_sql_value(True) == "TRUE"
    assert _format_sql_value(False) == "FALSE"
    assert _format_sql_value(42) == "42"
    assert _format_sql_value(3.14) == "3.14"
    assert _format_sql_value("O'Connor\\Test") == "'O''Connor\\\\Test'"

    tuples = _split_multiple_tuples("(1, 'a'), (2, 'b')")
    assert len(tuples) == 2
    assert tuples[0][2] == "(1, 'a')"
    assert tuples[1][2] == "(2, 'b')"


def test_plugin_loader_error_handling():
    with patch("importlib.metadata.entry_points") as mock_eps:
        mock_ep = MagicMock()
        mock_ep.name = "broken_plugin"
        mock_ep.load.side_effect = Exception("Failed to load")
        mock_eps.return_value = [mock_ep]
        StrategyRegistry._plugins_loaded = False
        loaded = StrategyRegistry.load_plugins()
        assert loaded == 0


def test_logging_setup():
    setup_logging(verbose=True)
    setup_logging(verbose=False)


def test_json_mask_strategy_nested_paths():
    strat = JSONMaskStrategy()
    ctx = TransformationContext(
        table_name="users",
        column_name="metadata",
        row_index=0,
        salt="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )

    doc = {
        "user": {"email": "john@example.com", "age": 30},
        "tags": ["admin", "staff"],
    }
    raw_json = json.dumps(doc)

    masked = strat.transform(
        raw_json,
        ctx,
        rules={
            "user.email": {"strategy": "nullify"},
            "user.age": {"strategy": "constant", "params": {"value_to_set": 99}},
        },
    )
    parsed = json.loads(masked)
    assert parsed["user"]["email"] is None
    assert parsed["user"]["age"] == 99

    # Handle None & invalid JSON string
    assert strat.transform(None, ctx) is None
    assert strat.transform("not json", ctx) == "not json"


def test_telemetry_with_mock_sdk():
    mock_tracer = MagicMock()
    mock_span = MagicMock()
    mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span

    CloakTelemetry._enabled = True
    CloakTelemetry._tracer = mock_tracer

    with CloakTelemetry.span("test_span", {"custom_key": "custom_val"}) as s:
        assert s == mock_span
    mock_span.set_attribute.assert_called_with("custom_key", "custom_val")

    # Reset
    CloakTelemetry._enabled = False
    CloakTelemetry._tracer = None


def test_cli_scan_and_bench(tmp_path: Path):
    csv_file = tmp_path / "data.csv"
    csv_file.write_text("id,email\n1,alice@example.com\n", encoding="utf-8")

    res_scan = runner.invoke(app, ["scan", str(csv_file), "--max-samples", "10"])
    assert res_scan.exit_code == 0
    assert "Found" in res_scan.stdout or "email" in res_scan.stdout

    res_bench = runner.invoke(app, ["bench", "--rows", "100"])
    assert res_bench.exit_code == 0
    assert "Benchmark Results" in res_bench.stdout


def test_json_mask_wildcards_and_lists():
    strat = JSONMaskStrategy()
    ctx = TransformationContext(
        table_name="t",
        column_name="c",
        row_index=0,
        salt="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )

    data = {
        "items": [{"name": "item1", "price": 10}, {"name": "item2", "price": 20}],
        "attributes": {"color": "red", "size": "M"},
    }

    # Test wildcard array [*] and wildcard dict *
    res = strat.transform(
        data,
        ctx,
        rules={
            "items[*].name": "nullify",
            "items[0].price": {"strategy": "constant", "params": {"value_to_set": 0}},
            "attributes.*": "nullify",
        },
    )
    assert res["items"][0]["name"] is None
    assert res["items"][1]["name"] is None
    assert res["items"][0]["price"] == 0
    assert res["attributes"]["color"] is None
    assert res["attributes"]["size"] is None

    # Error handling raise
    with pytest.raises(ValueError):
        strat.transform("{bad_json}", ctx, rules={"a": "nullify"}, error_handling="raise")


def test_engine_table_truncate_and_conditions():
    salt = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    cfg = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt=salt),
        tables={
            "audit_logs": TableRule(truncate=True, columns={}),
            "users": TableRule(
                columns={
                    "email": ColumnRule(
                        strategy="constant",
                        params={"value_to_set": "redacted@corp.org"},
                        condition="id > 10",
                    )
                }
            ),
        },
    )
    engine = CloakEngine(cfg)
    assert engine.should_truncate_table("audit_logs") is True
    assert engine.should_truncate_table("users") is False

    # Conditional masking
    r1 = engine.mask_record("users", {"id": 5, "email": "keep@corp.org"})
    assert r1["email"] == "keep@corp.org"  # Condition id > 10 is False

    r2 = engine.mask_record("users", {"id": 15, "email": "change@corp.org"})
    assert r2["email"] == "redacted@corp.org"  # Condition id > 10 is True


def test_telemetry_structured_logging_init():
    setup_structured_logging()
    logger = logging.getLogger("cloakdb")
    assert any(isinstance(h.formatter, JSONFormatter) for h in logger.handlers)

    # Initialize telemetry with endpoint
    with patch("os.getenv", return_value="http://localhost:4317"):
        CloakTelemetry.initialize(endpoint="http://localhost:4317")
        assert CloakTelemetry._enabled is True
        CloakTelemetry.initialize(enabled=False)
        assert CloakTelemetry._enabled is False


def test_generator_scan_live_db(tmp_path: Path):
    from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine

    db_file = tmp_path / "scan_test.db"
    db_url = f"sqlite:///{db_file}"
    engine = create_engine(db_url)
    meta = MetaData()
    users = Table(
        "users", meta,
        Column("id", Integer, primary_key=True),
        Column("email", String(100)),
    )
    meta.create_all(engine)

    with engine.connect() as conn:
        conn.execute(users.insert(), [{"id": 1, "email": "alice@test.com"}, {"id": 2, "email": "bob@test.com"}])
        conn.commit()

    generator = ConfigGenerator()
    detections = generator.scan_live_db(db_url, data_only=True)
    assert "users" in detections
    assert any(res.column_name == "email" for res in detections["users"])


def test_faker_strategy_unsupported_provider():
    from cloakdb.strategies.synthetic import SyntheticFakerStrategy
    strat = SyntheticFakerStrategy()
    ctx = TransformationContext(
        table_name="t",
        column_name="c",
        row_index=0,
        salt="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )
    res = strat.transform("fallback_val", ctx, provider="completely_invalid_provider_12345")
    assert isinstance(res, str) and len(res) > 0


def test_security_zeroize_memory_all_types():
    import ctypes

    # Bytearray
    b = bytearray(b"sensitive_password")
    zeroize_memory(b)
    assert b == bytearray(len(b))

    # Ctypes array
    c_arr = (ctypes.c_char * 8)(*b"secret12")
    zeroize_memory(c_arr)

    # List & dict
    lst = ["a", "b", "c"]
    zeroize_memory(lst)
    assert lst == []

    dct = {"k": "v"}
    zeroize_memory(dct)
    assert dct == {}

    # None and other primitives (safe no-op)
    zeroize_memory(None)
    zeroize_memory("string_immutable")


def test_logger_setup():
    setup_logging(verbose=True)
    setup_logging(verbose=False)
