"""Tests for streaming SQL dump parsing, CSV/JSONL parsing, and SQL value escaping."""

import io
from pathlib import Path

import pytest

from cloakdb.config.models import CloakConfig, ColumnRule, GlobalConfig, TableRule
from cloakdb.core.engine import CloakEngine
from cloakdb.parsers.csv_stream import CSVStreamParser
from cloakdb.parsers.json_stream import JSONLinesStreamParser
from cloakdb.parsers.sql_dump import (
    SQLDumpStreamParser,
    _format_sql_value,
    _parse_sql_value,
    _split_sql_values_row,
)


def test_sql_dump_copy_and_insert_streaming(postgres_dump_file: Path):
    config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt="sql-test-salt"),
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
                    "shipping_address": ColumnRule(
                        strategy="constant", params={"value_to_set": "REDACTED ADDRESS"}
                    ),
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
        global_settings=GlobalConfig(salt="sql-test-salt"),
        tables={
            "customers": TableRule(
                columns={
                    "email": ColumnRule(strategy="email_mask"),
                    "ssn": ColumnRule(
                        strategy="pattern_mask", params={"keep_first": 0, "keep_last": 4}
                    ),
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


def test_sql_value_parsing_and_formatting():
    assert _parse_sql_value("NULL") is None
    assert _parse_sql_value("null") is None
    assert _parse_sql_value("TRUE") is True
    assert _parse_sql_value("FALSE") is False
    assert _parse_sql_value("123") == 123
    assert _parse_sql_value("123.45") == 123.45
    assert _parse_sql_value("'hello world'") == "hello world"
    assert _parse_sql_value("'it''s fine'") == "it's fine"

    assert _format_sql_value(None) == "NULL"
    assert _format_sql_value(True) == "TRUE"
    assert _format_sql_value(False) == "FALSE"
    assert _format_sql_value(42) == "42"
    assert _format_sql_value(3.14) == "3.14"
    assert _format_sql_value("O'Reilly") == "'O''Reilly'"


def test_split_sql_values_row():
    row = "(1, 'John Doe', 'O''Connor, Jr.', NULL, 45.50)"
    tokens = _split_sql_values_row(row)
    assert len(tokens) == 5
    assert tokens[0][2].strip() == "1"
    assert tokens[1][2].strip() == "'John Doe'"
    assert tokens[2][2].strip() == "'O''Connor, Jr.'"
    assert tokens[3][2].strip() == "NULL"
    assert tokens[4][2].strip() == "45.50"


def test_csv_stream_parser():
    csv_data = "id,name,email\n1,Alice,alice@example.com\n2,Bob,bob@example.com\n"
    config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt="sql-test-salt"),
        tables={
            "users": TableRule(
                columns={
                    "email": ColumnRule(
                        strategy="constant", params={"value_to_set": "masked@domain.com"}
                    )
                }
            )
        },
    )
    engine = CloakEngine(config)
    parser = CSVStreamParser(table_name="users")

    in_stream = io.StringIO(csv_data)
    out_stream = io.StringIO()
    parser.process_stream(in_stream, out_stream, engine)

    output = out_stream.getvalue()
    assert "id,name,email" in output
    assert "alice@example.com" not in output
    assert "masked@domain.com" in output


def test_json_stream_parser():
    json_lines = '{"id": 1, "secret": "abc123xyz"}\n{"id": 2, "secret": "def456uvw"}\n'
    config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt="sql-test-salt"),
        tables={"tokens": TableRule(columns={"secret": ColumnRule(strategy="nullify")})},
    )
    engine = CloakEngine(config)
    parser = JSONLinesStreamParser(table_name="tokens")

    in_stream = io.StringIO(json_lines)
    out_stream = io.StringIO()
    parser.process_stream(in_stream, out_stream, engine)

    output = out_stream.getvalue()
    assert "abc123xyz" not in output
    assert "def456uvw" not in output
    assert '"secret": null' in output or '"secret": "NULL"' in output or "null" in output


def test_sql_parser_semicolon_inside_string_literal():
    fixtures_dir = Path(__file__).parent / "fixtures"
    sql_path = fixtures_dir / "semicolon_in_string.sql"
    sql_content = sql_path.read_text(encoding="utf-8")

    config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt="sql-test-salt"),
        tables={
            "messages": TableRule(
                columns={
                    "sender_email": ColumnRule(strategy="email_mask"),
                }
            )
        },
    )
    engine = CloakEngine(config)
    parser = SQLDumpStreamParser()

    in_stream = io.StringIO(sql_content)
    out_stream = io.StringIO()
    parser.process_stream(in_stream, out_stream, engine)

    output = out_stream.getvalue()
    # Both rows must be processed and masked, not truncated or skipped
    assert "alice@example.com" not in output
    assert "bob@example.com" not in output
    assert "Hello; this is a test; with semicolons;" in output
    assert "Second message; still in insert block;" in output
    assert engine.stats.rows_processed == 2


def test_sql_parser_multiline_string_with_newlines():
    fixtures_dir = Path(__file__).parent / "fixtures"
    sql_path = fixtures_dir / "multiline_string.sql"
    sql_content = sql_path.read_text(encoding="utf-8")

    config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt="sql-test-salt"),
        tables={
            "posts": TableRule(
                columns={
                    "author_email": ColumnRule(strategy="email_mask"),
                }
            )
        },
    )
    engine = CloakEngine(config)
    parser = SQLDumpStreamParser()

    in_stream = io.StringIO(sql_content)
    out_stream = io.StringIO()
    parser.process_stream(in_stream, out_stream, engine)

    output = out_stream.getvalue()
    # Both rows must be processed and masked properly
    assert "carol@example.com" not in output
    assert "dave@example.com" not in output
    assert "Paragraph 1: Welcome!" in output
    assert "Paragraph 2: This is a multi-line body with real newlines." in output
    assert "Paragraph 3: Semicolons; and (parentheses) inside quotes." in output
    assert "Single line body" in output
    assert engine.stats.rows_processed == 2


def test_sql_parser_semicolon_and_escaped_single_quotes():
    fixtures_dir = Path(__file__).parent / "fixtures"
    sql_path = fixtures_dir / "semicolon_and_escaped_quote.sql"
    sql_content = sql_path.read_text(encoding="utf-8")

    config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt="sql-test-salt"),
        tables={
            "comments": TableRule(
                columns={
                    "author_email": ColumnRule(strategy="email_mask"),
                }
            )
        },
    )
    engine = CloakEngine(config)
    parser = SQLDumpStreamParser()

    in_stream = io.StringIO(sql_content)
    out_stream = io.StringIO()
    parser.process_stream(in_stream, out_stream, engine)

    output = out_stream.getvalue()
    # All rows must be processed without premature splitting on embedded semicolons
    assert "alice@example.com" not in output
    assert "bob@example.com" not in output
    assert "carol@example.com" not in output
    assert "It''s a great feature; highly recommended!" in output
    assert "Customer''s feedback; status: resolved; notes: don''t forget follow-up." in output
    assert "Final note; let''s verify." in output
    assert engine.stats.rows_processed == 3


def test_csv_and_json_stream_parser_tracks_bytes():
    config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt="test-salt"),
        tables={"users": TableRule(columns={"email": ColumnRule(strategy="nullify")})},
    )

    # 1. Test CSV byte tracking
    csv_engine = CloakEngine(config)
    csv_parser = CSVStreamParser(table_name="users")
    csv_input = io.StringIO("id,email\n1,alice@example.com\n2,bob@example.com\n")
    csv_output = io.StringIO()
    csv_parser.process_stream(csv_input, csv_output, csv_engine)
    assert csv_engine.stats.bytes_processed > 0
    assert csv_engine.stats.rows_processed == 2

    # 2. Test JSONL byte tracking
    json_engine = CloakEngine(config)
    json_parser = JSONLinesStreamParser(table_name="users")
    json_input = io.StringIO(
        '{"id": 1, "email": "alice@example.com"}\n{"id": 2, "email": "bob@example.com"}\n'
    )
    json_output = io.StringIO()
    json_parser.process_stream(json_input, json_output, json_engine)
    assert json_engine.stats.bytes_processed > 0
    assert json_engine.stats.rows_processed == 2


def test_json_stream_parser_malformed_line_error():
    config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt="test-salt"),
        tables={"users": TableRule(columns={"email": ColumnRule(strategy="nullify")})},
    )
    engine = CloakEngine(config)
    parser = JSONLinesStreamParser(table_name="users")

    # Line 2 is intentionally malformed JSON
    bad_jsonl = '{"id": 1, "email": "valid@test.com"}\n{id: 2, invalid_json_syntax}\n{"id": 3}\n'
    in_stream = io.StringIO(bad_jsonl)
    out_stream = io.StringIO()

    with pytest.raises(ValueError) as exc_info:
        parser.process_stream(in_stream, out_stream, engine)

    error_msg = str(exc_info.value)
    assert "line 2" in error_msg
    assert "Malformed JSON on line 2" in error_msg
    assert "{id: 2" in error_msg
