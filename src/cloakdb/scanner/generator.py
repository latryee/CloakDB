"""Auto-configuration generator based on scanner results."""

from __future__ import annotations

import csv
import secrets
from pathlib import Path
from typing import Any

from cloakdb.config.models import (
    CloakConfig,
    ColumnRule,
    ConsistencyGroup,
    GlobalConfig,
    TableRule,
)
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
from cloakdb.utils.security import compute_salt_fingerprint


class ConfigGenerator:
    """Scans datasets and generates complete CloakConfig configurations."""

    def __init__(self, detector: PIIDetector | None = None):
        self.detector = detector or PIIDetector()

    def scan_sql_dump(
        self, file_path: str | Path, max_lines: int = 2000, data_only: bool = False
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

        return self._detect_from_samples(table_samples, data_only=data_only)

    def scan_csv(
        self,
        file_path: str | Path,
        table_name: str = "data",
        max_rows: int = 100,
        data_only: bool = False,
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

        return self._detect_from_samples(table_samples, data_only=data_only)

    def scan_parquet(
        self, file_path: str | Path, max_rows: int = 100, data_only: bool = False
    ) -> dict[str, list[PIIDetectionResult]]:
        """Samples rows from an Apache Parquet file and detects PII."""
        try:
            import pyarrow.parquet as pq
        except ImportError as err:
            raise ImportError(
                "Apache Parquet support requires 'pyarrow'. Install with: pip install 'cloakdb[parquet]'"
            ) from err

        path = Path(file_path)
        table_name = path.stem
        pq_file = pq.ParquetFile(str(path))
        table_samples: dict[str, dict[str, list[Any]]] = {table_name: {}}

        for batch in pq_file.iter_batches(batch_size=max_rows):
            pydict = batch.to_pydict()
            for col, vals in pydict.items():
                if col not in table_samples[table_name]:
                    table_samples[table_name][col] = []
                table_samples[table_name][col].extend(vals[:max_rows])
            break

        return self._detect_from_samples(table_samples, data_only=data_only)

    def scan_live_db(
        self, connection_url: str, sample_limit: int = 50, data_only: bool = False
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

        return self._detect_from_samples(table_samples, data_only=data_only)

    def _detect_from_samples(
        self,
        table_samples: dict[str, dict[str, list[Any]]],
        data_only: bool = False,
    ) -> dict[str, list[PIIDetectionResult]]:
        results: dict[str, list[PIIDetectionResult]] = {}
        for tbl_name, col_dict in table_samples.items():
            tbl_results = []
            for col_name, samples in col_dict.items():
                res = self.detector.detect_column(col_name, samples, data_only=data_only)
                if res is not None:
                    tbl_results.append(res)
            if tbl_results:
                results[tbl_name] = tbl_results
        return results

    def infer_foreign_keys_sql_dump(self, file_path: str | Path) -> list[ConsistencyGroup]:
        """Parses DDL statements from a SQL dump to automatically extract Foreign Key relationships."""
        path = Path(file_path)
        if not path.exists():
            return []

        import re

        groups: list[ConsistencyGroup] = []
        seen_pairs: set[str] = set()

        alter_fk_pattern = re.compile(
            r"ALTER\s+TABLE\s+(?:ONLY\s+)?([`\"\[]?\w+[`\"\]]?)\s+ADD\s+(?:CONSTRAINT\s+[`\"\[]?\w+[`\"\]]?\s+)?FOREIGN\s+KEY\s*\(([^)]+)\)\s*REFERENCES\s*([`\"\[]?\w+[`\"\]]?)\s*\(([^)]+)\)",
            re.IGNORECASE,
        )
        create_table_start = re.compile(
            r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([`\"\[]?\w+[`\"\]]?)", re.IGNORECASE
        )
        table_fk_pattern = re.compile(
            r"FOREIGN\s+KEY\s*\(([^)]+)\)\s*REFERENCES\s*([`\"\[]?\w+[`\"\]]?)\s*\(([^)]+)\)",
            re.IGNORECASE,
        )
        inline_fk_pattern = re.compile(
            r"^\s*([`\"\[]?\w+[`\"\]]?)\s+[\w\(\)\s]+\s+REFERENCES\s+([`\"\[]?\w+[`\"\]]?)\s*\(([^)]+)\)",
            re.IGNORECASE,
        )

        current_create_table: str | None = None

        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                # 1. Check ALTER TABLE FK
                alter_match = alter_fk_pattern.search(line)
                if alter_match:
                    src_tbl = _clean_identifier(alter_match.group(1))
                    src_cols = [_clean_identifier(c) for c in alter_match.group(2).split(",")]
                    dst_tbl = _clean_identifier(alter_match.group(3))
                    dst_cols = [_clean_identifier(c) for c in alter_match.group(4).split(",")]
                    self._add_inferred_fk_group(
                        groups, seen_pairs, src_tbl, src_cols, dst_tbl, dst_cols
                    )
                    continue

                # 2. Track CREATE TABLE context
                create_match = create_table_start.search(line)
                if create_match:
                    current_create_table = _clean_identifier(create_match.group(1))
                    continue

                if current_create_table:
                    if ";" in line and ")" in line:
                        table_fk_match = table_fk_pattern.search(line)
                        if table_fk_match:
                            src_cols = [
                                _clean_identifier(c) for c in table_fk_match.group(1).split(",")
                            ]
                            dst_tbl = _clean_identifier(table_fk_match.group(2))
                            dst_cols = [
                                _clean_identifier(c) for c in table_fk_match.group(3).split(",")
                            ]
                            self._add_inferred_fk_group(
                                groups,
                                seen_pairs,
                                current_create_table,
                                src_cols,
                                dst_tbl,
                                dst_cols,
                            )
                        current_create_table = None
                        continue

                    table_fk_match = table_fk_pattern.search(line)
                    if table_fk_match:
                        src_cols = [
                            _clean_identifier(c) for c in table_fk_match.group(1).split(",")
                        ]
                        dst_tbl = _clean_identifier(table_fk_match.group(2))
                        dst_cols = [
                            _clean_identifier(c) for c in table_fk_match.group(3).split(",")
                        ]
                        self._add_inferred_fk_group(
                            groups, seen_pairs, current_create_table, src_cols, dst_tbl, dst_cols
                        )
                        continue

                    inline_match = inline_fk_pattern.search(line)
                    if inline_match:
                        col_name = _clean_identifier(inline_match.group(1))
                        dst_tbl = _clean_identifier(inline_match.group(2))
                        dst_col = _clean_identifier(inline_match.group(3))
                        self._add_inferred_fk_group(
                            groups, seen_pairs, current_create_table, [col_name], dst_tbl, [dst_col]
                        )
                        continue

        return groups

    def infer_foreign_keys_live_db(self, connection_url: str) -> list[ConsistencyGroup]:
        """Introspects a live database to automatically extract Foreign Key relationships."""
        from sqlalchemy import inspect

        connector = LiveDatabaseConnector(connection_url)
        inspector = inspect(connector.engine)
        groups: list[ConsistencyGroup] = []
        seen_pairs: set[str] = set()

        for tbl_name in inspector.get_table_names():
            try:
                fks = inspector.get_foreign_keys(tbl_name)
            except Exception:
                continue

            for fk in fks:
                dst_tbl = fk.get("referred_table")
                src_cols = fk.get("constrained_columns", [])
                dst_cols = fk.get("referred_columns", [])
                if not dst_tbl or not src_cols or not dst_cols:
                    continue

                self._add_inferred_fk_group(
                    groups, seen_pairs, tbl_name, src_cols, dst_tbl, dst_cols
                )

        return groups

    def _add_inferred_fk_group(
        self,
        groups: list[ConsistencyGroup],
        seen_pairs: set[str],
        src_tbl: str,
        src_cols: list[str],
        dst_tbl: str,
        dst_cols: list[str],
    ) -> None:
        from cloakdb.config.models import ConsistencyGroup

        if len(src_cols) == 1 and len(dst_cols) == 1:
            col_src = f"{src_tbl}.{src_cols[0]}"
            col_dst = f"{dst_tbl}.{dst_cols[0]}"
            pair_key = f"{col_dst} -> {col_src}"
            if pair_key in seen_pairs:
                return
            seen_pairs.add(pair_key)
            grp_name = f"cg_{dst_tbl}_{dst_cols[0]}"
            groups.append(
                ConsistencyGroup(
                    name=grp_name,
                    columns=[col_dst, col_src],
                    strategy="deterministic_hash",
                )
            )
        elif len(src_cols) > 1:
            comp_src = f"{src_tbl}.({', '.join(src_cols)})"
            comp_dst = f"{dst_tbl}.({', '.join(dst_cols)})"
            pair_key = f"{comp_dst} -> {comp_src}"
            if pair_key in seen_pairs:
                return
            seen_pairs.add(pair_key)
            grp_name = f"cg_composite_{dst_tbl}_{'_'.join(dst_cols)}"
            groups.append(
                ConsistencyGroup(
                    name=grp_name,
                    columns=[comp_dst, comp_src],
                    strategy="deterministic_hash",
                )
            )

    def generate_config_from_detections(
        self,
        detections: dict[str, list[PIIDetectionResult]],
        locale: str = "en_US",
        target: str | None = None,
        infer_fks: bool = False,
    ) -> CloakConfig:
        """Constructs a CloakConfig object from detection results and optional FK inference."""
        tables_dict: dict[str, TableRule] = {}

        for tbl_name, results in detections.items():
            col_rules: dict[str, ColumnRule] = {}
            for res in results:
                col_rules[res.column_name] = ColumnRule(
                    strategy=res.recommended_strategy,
                    params=res.recommended_params,
                )
            tables_dict[tbl_name] = TableRule(columns=col_rules)

        consistency_groups: list[ConsistencyGroup] = []
        if infer_fks and target:
            if "://" in target:
                consistency_groups = self.infer_foreign_keys_live_db(target)
            elif not target.endswith(".csv") and not target.endswith(".jsonl"):
                consistency_groups = self.infer_foreign_keys_sql_dump(target)

        random_salt = secrets.token_hex(32)
        return CloakConfig(
            version="1",
            global_settings=GlobalConfig(
                salt=random_salt,
                salt_fingerprint=compute_salt_fingerprint(random_salt),
                locale=locale,
            ),
            tables=tables_dict,
            consistency_groups=consistency_groups,
        )
