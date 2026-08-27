"""Tests for streaming SQL dump parsing and escaping."""

import io
from pathlib import Path
from cloakdb.config.models import CloakConfig, ColumnRule, TableRule
from cloakdb.core.engine import CloakEngine
from cloakdb.parsers.sql_dump import SQLDumpStreamParser


def test_sql_dump_copy_and_insert_streaming(postgres_dump_file: Path):
    config = CloakConfig(
        version="1",
        tables={
            "users": TableRule(
                columns={
                    "email": ColumnRule(strategy="faker", params={"provider": "email"}),
                    "full_name": ColumnRule(strategy="faker", params={"provider": "name"}),
                    "credit_card": ColumnRule(strategy="credit_card_mask"),
                }
            ),
            "orders": TableRule(
                columns={
                    "shipping_address": ColumnRule(strategy="constant", params={"value_to_set": "REDACTED ADDRESS"}),
                }
            ),
        },
    )

    engine = CloakEngine(config)
    parser = SQLDumpStreamParser()

    in_content = postgres_dump_file.read_text(encoding="utf-8")
    in_stream = io.StringIO(in_content)
    out_stream = io.StringIO()

    parser.process_stream(in_stream, out_stream, engine)
    output = out_stream.getvalue()

    # Assertions
    assert "john.doe@example.com" not in output
    assert "Alice Smith" not in output
    assert "4532015012345678" not in output
    assert "****-****-****-" in output
    assert "REDACTED ADDRESS" in output
    assert "CREATE TABLE public.users" in output
    assert "CREATE TABLE public.orders" in output
    assert engine.stats.rows_processed > 0
    assert engine.stats.cells_masked > 0


def test_mysql_multi_insert_streaming(mysql_dump_file: Path):
    config = CloakConfig(
        version="1",
        tables={
            "customers": TableRule(
                columns={
                    "email": ColumnRule(strategy="email_mask"),
                    "ssn": ColumnRule(strategy="pattern_mask", params={"keep_first": 0, "keep_last": 4}),
                    "secret_token": ColumnRule(strategy="nullify"),
                }
            )
        },
    )

    engine = CloakEngine(config)
    parser = SQLDumpStreamParser()

    in_content = mysql_dump_file.read_text(encoding="utf-8")
    in_stream = io.StringIO(in_content)
    out_stream = io.StringIO()

    parser.process_stream(in_stream, out_stream, engine)
    output = out_stream.getvalue()

    assert "customer1@test.com" not in output
    assert "secret_abc_123" not in output
    assert "NULL" in output
    assert "INSERT INTO `customers`" in output
