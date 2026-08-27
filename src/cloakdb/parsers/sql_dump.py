"""High-performance streaming SQL dump parser supporting PostgreSQL, MySQL, and SQLite."""

from __future__ import annotations

import re
from typing import Any, Callable, IO, List, Optional, Tuple
from cloakdb.core.engine import CloakEngine
from cloakdb.parsers.base import BaseStreamParser

# Regex patterns for SQL constructs
_COPY_PATTERN = re.compile(
    r"^COPY\s+(?:(?P<schema>[\w\"]+)\.)?(?P<table>[\w\"]+)\s*\((?P<columns>[^\)]+)\)\s+FROM\s+stdin;",
    re.IGNORECASE,
)

_INSERT_HEADER_PATTERN = re.compile(
    r"^INSERT\s+INTO\s+(?:(?P<schema>[\w\"`]+)\.)?(?P<table>[\w\"`]+)\s*(?:\((?P<columns>[^\)]+)\))?\s+VALUES\s*",
    re.IGNORECASE,
)


def _clean_identifier(ident: str) -> str:
    return ident.strip().strip('"').strip('`').strip('[]')


def _parse_column_list(cols_str: str) -> List[str]:
    return [_clean_identifier(c) for c in cols_str.split(",") if c.strip()]


def _parse_sql_value(raw: str) -> Any:
    raw = raw.strip()
    if raw.upper() == "NULL":
        return None
    if raw.upper() in ("TRUE", "FALSE"):
        return raw.upper() == "TRUE"
    if (raw.startswith("'") and raw.endswith("'")) or (raw.startswith('"') and raw.endswith('"')):
        # String literal: unescape SQL escapes
        content = raw[1:-1]
        content = (
            content.replace("''", "'")
            .replace(r"\'", "'")
            .replace(r"\\", "\\")
            .replace(r"\n", "\n")
            .replace(r"\r", "\r")
            .replace(r"\t", "\t")
        )
        return content
    try:
        if "." in raw or "e" in raw.lower():
            return float(raw)
        return int(raw)
    except ValueError:
        return raw


def _format_sql_value(val: Any) -> str:
    if val is None:
        return "NULL"
    if isinstance(val, bool):
        return "TRUE" if val else "FALSE"
    if isinstance(val, (int, float)):
        return str(val)
    # String formatting with proper SQL escaping
    s = str(val).replace("\\", "\\\\").replace("'", "''").replace("\n", "\\n").replace("\r", "\\r")
    return f"'{s}'"


def _split_sql_values_row(values_clause: str) -> List[Tuple[int, int, str]]:
    """Splits a tuple '(val1, val2, ...)' into individual raw value tokens with their span positions."""
    s = values_clause.strip()
    if s.startswith("(") and s.endswith(")"):
        s = s[1:-1]

    tokens: List[Tuple[int, int, str]] = []
    in_quote = False
    quote_char = ""
    is_escaped = False
    start_idx = 0
    i = 0
    n = len(s)

    while i < n:
        char = s[i]
        if is_escaped:
            is_escaped = False
            i += 1
            continue

        if char == "\\" and in_quote:
            is_escaped = True
            i += 1
            continue

        if char in ("'", '"'):
            if not in_quote:
                in_quote = True
                quote_char = char
            elif quote_char == char:
                # Check for double quote escape ''
                if i + 1 < n and s[i + 1] == char:
                    i += 2
                    continue
                in_quote = False
            i += 1
            continue

        if char == "," and not in_quote:
            token = s[start_idx:i]
            tokens.append((start_idx, i, token))
            start_idx = i + 1
            i += 1
            continue

        i += 1

    if start_idx < n:
        tokens.append((start_idx, n, s[start_idx:n]))

    return tokens


def _split_multiple_tuples(rest_clause: str) -> List[Tuple[int, int, str]]:
    """Splits multi-row insert clauses: (a, b), (c, d), (e, f); into individual tuple strings and spans."""
    tuples = []
    in_quote = False
    quote_char = ""
    is_escaped = False
    paren_depth = 0
    tuple_start = -1
    i = 0
    n = len(rest_clause)

    while i < n:
        char = rest_clause[i]
        if is_escaped:
            is_escaped = False
            i += 1
            continue

        if char == "\\" and in_quote:
            is_escaped = True
            i += 1
            continue

        if char in ("'", '"'):
            if not in_quote:
                in_quote = True
                quote_char = char
            elif quote_char == char:
                if i + 1 < n and rest_clause[i + 1] == char:
                    i += 2
                    continue
                in_quote = False
            i += 1
            continue

        if not in_quote:
            if char == "(":
                if paren_depth == 0:
                    tuple_start = i
                paren_depth += 1
            elif char == ")":
                paren_depth -= 1
                if paren_depth == 0 and tuple_start != -1:
                    tuples.append((tuple_start, i + 1, rest_clause[tuple_start : i + 1]))
                    tuple_start = -1

        i += 1

    return tuples


class SQLDumpStreamParser(BaseStreamParser):
    """Streaming SQL dump parser for MySQL, PostgreSQL, and SQLite dumps."""

    def __init__(self, default_schema: str = "public"):
        self.default_schema = default_schema

    def process_stream(
        self,
        input_stream: IO[str],
        output_stream: IO[str],
        engine: CloakEngine,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        in_copy_mode = False
        copy_table = ""
        copy_columns: List[str] = []
        copy_truncate = False

        in_insert_mode = False
        insert_table = ""
        insert_columns: List[str] = []
        insert_truncate = False

        row_count = 0
        bytes_count = 0

        for line in input_stream:
            line_len = len(line.encode("utf-8"))
            bytes_count += line_len
            engine.stats.bytes_processed += line_len

            # 1. Handle PostgreSQL COPY mode
            if in_copy_mode:
                if line.strip() == r"\.":
                    in_copy_mode = False
                    if not copy_truncate:
                        output_stream.write(line)
                    continue

                if copy_truncate:
                    continue

                has_newline = line.endswith("\n")
                raw_line = line[:-1] if has_newline else line
                cells = raw_line.split("\t")

                parsed_values = []
                for cell in cells:
                    if cell == r"\N":
                        parsed_values.append(None)
                    else:
                        unescaped = (
                            cell.replace(r"\n", "\n")
                            .replace(r"\r", "\r")
                            .replace(r"\t", "\t")
                            .replace(r"\\", "\\")
                        )
                        parsed_values.append(unescaped)

                masked_values = engine.mask_row_values(
                    table_name=copy_table,
                    column_names=copy_columns,
                    row_values=parsed_values,
                    row_index=row_count,
                )

                formatted_cells = []
                for val in masked_values:
                    if val is None:
                        formatted_cells.append(r"\N")
                    else:
                        s = (
                            str(val)
                            .replace("\\", "\\\\")
                            .replace("\t", r"\t")
                            .replace("\n", r"\n")
                            .replace("\r", r"\r")
                        )
                        formatted_cells.append(s)

                out_line = "\t".join(formatted_cells) + ("\n" if has_newline else "")
                output_stream.write(out_line)
                row_count += 1
                if progress_callback and row_count % 500 == 0:
                    progress_callback(500, bytes_count)
                continue

            # 2. Check for start of COPY statement
            copy_match = _COPY_PATTERN.match(line.strip())
            if copy_match:
                copy_table = _clean_identifier(copy_match.group("table"))
                cols_raw = copy_match.group("columns")
                copy_columns = _parse_column_list(cols_raw)
                copy_truncate = engine.should_truncate_table(copy_table)
                in_copy_mode = True
                output_stream.write(line)
                continue

            # 3. Handle multi-line continuing INSERT mode
            if in_insert_mode:
                if insert_truncate:
                    if ";" in line:
                        in_insert_mode = False
                    continue

                tuples = _split_multiple_tuples(line)
                if tuples:
                    new_line = self._mask_tuples_in_string(
                        raw_str=line,
                        tuples=tuples,
                        table_name=insert_table,
                        column_names=insert_columns,
                        engine=engine,
                        row_start_index=row_count,
                    )
                    row_count += len(tuples)
                    output_stream.write(new_line)
                else:
                    output_stream.write(line)

                if ";" in line:
                    in_insert_mode = False
                continue

            # 4. Check for start of INSERT INTO statement
            insert_match = _INSERT_HEADER_PATTERN.match(line)
            if insert_match:
                tbl_name = _clean_identifier(insert_match.group("table"))
                insert_truncate = engine.should_truncate_table(tbl_name)

                cols_raw = insert_match.group("columns")
                if cols_raw:
                    col_names = _parse_column_list(cols_raw)
                else:
                    tbl_rule = engine.get_table_rule(tbl_name)
                    col_names = list(tbl_rule.columns.keys()) if (tbl_rule and tbl_rule.columns) else []

                insert_table = tbl_name
                insert_columns = col_names

                if insert_truncate:
                    if ";" not in line:
                        in_insert_mode = True
                    continue

                prefix_len = insert_match.end()
                header = line[:prefix_len]
                rest = line[prefix_len:]

                tuples = _split_multiple_tuples(rest)
                if tuples:
                    masked_rest = self._mask_tuples_in_string(
                        raw_str=rest,
                        tuples=tuples,
                        table_name=tbl_name,
                        column_names=col_names,
                        engine=engine,
                        row_start_index=row_count,
                    )
                    row_count += len(tuples)
                    output_stream.write(f"{header}{masked_rest}")
                else:
                    output_stream.write(line)

                if ";" not in line:
                    in_insert_mode = True
                continue

            # 5. Standard DDL / comment / other line
            output_stream.write(line)

        if progress_callback:
            progress_callback(0, bytes_count)

    def _mask_tuples_in_string(
        self,
        raw_str: str,
        tuples: List[Tuple[int, int, str]],
        table_name: str,
        column_names: List[str],
        engine: CloakEngine,
        row_start_index: int,
    ) -> str:
        """Replaces tuple values in a string segment with their masked equivalents."""
        out_segments = []
        last_idx = 0

        for t_idx, (start, end, tup_str) in enumerate(tuples):
            out_segments.append(raw_str[last_idx:start])

            raw_val_tokens = _split_sql_values_row(tup_str)
            row_vals = [_parse_sql_value(tok[2]) for tok in raw_val_tokens]

            if column_names:
                effective_cols = column_names[: len(row_vals)]
            else:
                effective_cols = [f"col_{i}" for i in range(len(row_vals))]

            masked_row = engine.mask_row_values(
                table_name=table_name,
                column_names=effective_cols,
                row_values=row_vals,
                row_index=row_start_index + t_idx,
            )
            formatted_row = [_format_sql_value(v) for v in masked_row]
            out_segments.append(f"({', '.join(formatted_row)})")
            last_idx = end

        out_segments.append(raw_str[last_idx:])
        return "".join(out_segments)
