"""Auto-configuration generator based on scanner results."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from cloakdb.config.models import CloakConfig, ColumnRule, GlobalConfig, TableRule
from cloakdb.connectors.live_db import LiveDatabaseConnector
from cloakdb.parsers.sql_dump import (
    _COPY_PATTERN,
    _INSERT_HEADER_PATTERN,
    _clean_identifier,
    _parse_column_list,
    _parse_sql_value,
    _split_multiple_tuples,
    _split_sql_values_row,
)
from cloakdb.scanner.detector import PIIDetectionResult, PIIDetector


class ConfigGenerator:
    """Scans datasets and generates complete CloakConfig configurations."""

    def __init__(self, detector: PIIDetector | None = None):
        self.detector = detector or PIIDetector()

    def scan_sql_dump(
        self, file_path: str | Path, max_lines: int = 2000
    ) -> dict[str, list[PIIDetectionResult]]:
        """Samples tables and columns from a SQL dump file and detects PII."""
        path = Path(file_path)
        table_samples: dict[str, dict[str, list[Any]]] = {}

        in_copy = False
        current_table = ""
        current_columns: list[str] = []

        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f):
                if line_no > max_lines:
                    break

                if in_copy:
                    if line.strip() == r"\.":
                        in_copy = False
                        continue
                    cells = line.rstrip("\n").split("\t")
                    for i, cell in enumerate(cells):
                        if i < len(current_columns):
                            col_name = current_columns[i]
                            val = None if cell == r"\N" else cell
                            table_samples[current_table][col_name].append(val)
                    continue

                copy_match = _COPY_PATTERN.match(line.strip())
                if copy_match:
                    current_table = _clean_identifier(copy_match.group("table"))
                    current_columns = _parse_column_list(copy_match.group("columns"))
                    if current_table not in table_samples:
                        table_samples[current_table] = {c: [] for c in current_columns}
                    in_copy = True
                    continue

                insert_match = _INSERT_HEADER_PATTERN.match(line)
                if insert_match:
                    tbl_name = _clean_identifier(insert_match.group("table"))
                    cols_raw = insert_match.group("columns")
                    cols = _parse_column_list(cols_raw) if cols_raw else []
                    if tbl_name not in table_samples:
                        table_samples[tbl_name] = {c: [] for c in cols}

                    rest = line[insert_match.end() :]
                    tuples = _split_multiple_tuples(rest)
                    for _, _, tup_str in tuples[:10]:
                        tokens = _split_sql_values_row(tup_str)
                        row_vals = [_parse_sql_value(t[2]) for t in tokens]
                        for idx, v in enumerate(row_vals):
                            col_name = cols[idx] if idx < len(cols) else f"col_{idx}"
                            if col_name not in table_samples[tbl_name]:
                                table_samples[tbl_name][col_name] = []
                            table_samples[tbl_name][col_name].append(v)

        return self._detect_from_samples(table_samples)

    def scan_csv(
        self, file_path: str | Path, table_name: str = "data", max_rows: int = 100
    ) -> dict[str, list[PIIDetectionResult]]:
        """Samples a CSV file and detects PII columns."""
        path = Path(file_path)
        table_samples: dict[str, dict[str, list[Any]]] = {table_name: {}}

        with path.open("r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if not header:
                return {}

            for col in header:
                table_samples[table_name][col] = []

            for row_no, row in enumerate(reader):
                if row_no > max_rows:
                    break
                for idx, cell in enumerate(row):
                    if idx < len(header):
                        table_samples[table_name][header[idx]].append(cell)

        return self._detect_from_samples(table_samples)

    def scan_live_db(
        self, connection_url: str, sample_limit: int = 50
    ) -> dict[str, list[PIIDetectionResult]]:
        """Samples all tables from a live database and detects PII."""
        connector = LiveDatabaseConnector(connection_url)
        table_samples: dict[str, dict[str, list[Any]]] = {}

        for tbl_name in connector.get_table_names():
            rows = connector.fetch_sample_rows(tbl_name, limit=sample_limit)
            if not rows:
                cols = connector.get_table_columns(tbl_name)
                table_samples[tbl_name] = {c["name"]: [] for c in cols}
            else:
                table_samples[tbl_name] = {}
                for col in rows[0].keys():
                    table_samples[tbl_name][col] = [r.get(col) for r in rows]

        return self._detect_from_samples(table_samples)

    def _detect_from_samples(
        self,
        table_samples: dict[str, dict[str, list[Any]]],
    ) -> dict[str, list[PIIDetectionResult]]:
        results: dict[str, list[PIIDetectionResult]] = {}
        for tbl_name, col_dict in table_samples.items():
            tbl_results = []
            for col_name, samples in col_dict.items():
                res = self.detector.detect_column(col_name, samples)
                if res is not None:
                    tbl_results.append(res)
            if tbl_results:
                results[tbl_name] = tbl_results
        return results

    def generate_config_from_detections(
        self,
        detections: dict[str, list[PIIDetectionResult]],
        locale: str = "en_US",
    ) -> CloakConfig:
        """Constructs a CloakConfig object from detection results."""
        tables_dict: dict[str, TableRule] = {}

        for tbl_name, results in detections.items():
            col_rules: dict[str, ColumnRule] = {}
            for res in results:
                col_rules[res.column_name] = ColumnRule(
                    strategy=res.recommended_strategy,
                    params=res.recommended_params,
                )
            tables_dict[tbl_name] = TableRule(columns=col_rules)

        return CloakConfig(
            version="1",
            global_settings=GlobalConfig(locale=locale),
            tables=tables_dict,
        )
