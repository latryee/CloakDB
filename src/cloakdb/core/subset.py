"""Referential data subsetting engine for creating coherent, reduced staging datasets."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO

from cloakdb.parsers.sql_dump import (
    _COPY_PATTERN,
    _INSERT_HEADER_PATTERN,
    _clean_identifier,
    _parse_column_list,
    _parse_sql_value,
    _split_multiple_tuples,
    _split_sql_values_row,
)
from cloakdb.scanner.generator import ConfigGenerator


@dataclass
class SubsetStats:
    """Statistics and metrics of the subsetting run."""

    root_table: str
    rows_in_per_table: dict[str, int] = field(default_factory=dict)
    rows_out_per_table: dict[str, int] = field(default_factory=dict)
    total_rows_read: int = 0
    total_rows_written: int = 0

    @property
    def reduction_percentage(self) -> float:
        if self.total_rows_read == 0:
            return 0.0
        return ((self.total_rows_read - self.total_rows_written) / self.total_rows_read) * 100.0


def _read_full_insert(first_line: str, line_iter: Any) -> str:
    """Buffers continuing lines of a multi-line INSERT statement until terminated by semicolon."""
    stmt = first_line
    if ";" in first_line:
        return stmt
    for next_line in line_iter:
        stmt += next_line
        if ";" in next_line:
            break
    return stmt


class RelationalSubsettingEngine:
    """Extracts a referentially consistent subset of tables from a SQL dump."""

    def __init__(
        self,
        root_table: str,
        limit: int = 1000,
        pk_column: str = "id",
        foreign_keys: list[tuple[str, str, str, str]] | None = None,
    ):
        """
        Args:
            root_table: The starting table from which the subset is sampled.
            limit: Maximum number of rows to retain from root_table.
            pk_column: Primary key column name for the root table (default 'id').
            foreign_keys: Optional list of (child_table, child_col, parent_table, parent_col).
        """
        self.root_table = root_table.lower()
        self.limit = limit
        self.pk_column = pk_column.lower()
        # child_table -> list of (child_col, parent_table, parent_col)
        self.downstream_fks: dict[str, list[tuple[str, str, str]]] = {}
        # parent_table -> list of (parent_col, child_table, child_col)
        self.upstream_fks: dict[str, list[tuple[str, str, str]]] = {}
        # table -> set of kept primary/foreign key values
        self.kept_keys: dict[str, set[str]] = {}

        if foreign_keys:
            for child_tbl, child_col, parent_tbl, parent_col in foreign_keys:
                self.add_foreign_key(child_tbl, child_col, parent_tbl, parent_col)

    def add_foreign_key(
        self, child_table: str, child_col: str, parent_table: str, parent_col: str
    ) -> None:
        """Registers a foreign key relationship."""
        c_tbl = child_table.lower()
        p_tbl = parent_table.lower()
        c_col = child_col.lower()
        p_col = parent_col.lower()

        if c_tbl not in self.downstream_fks:
            self.downstream_fks[c_tbl] = []
        self.downstream_fks[c_tbl].append((c_col, p_tbl, p_col))

        if p_tbl not in self.upstream_fks:
            self.upstream_fks[p_tbl] = []
        self.upstream_fks[p_tbl].append((p_col, c_tbl, c_col))

    def infer_foreign_keys_from_dump(self, file_path: str | Path) -> None:
        """Infers foreign keys from DDL and naming conventions in a SQL dump."""
        generator = ConfigGenerator()
        consistency_groups = generator.infer_foreign_keys_sql_dump(file_path)
        for cg in consistency_groups:
            # Formats: "table.col"
            if len(cg.columns) == 2:
                dst_tbl, dst_col = cg.columns[0].split(".", 1)
                src_tbl, src_col = cg.columns[1].split(".", 1)
                self.add_foreign_key(dst_tbl, dst_col, src_tbl, src_col)

    def subset_sql_dump(
        self,
        input_path: str | Path,
        output_path: str | Path,
    ) -> SubsetStats:
        """Performs two-pass referential subsetting on a SQL dump."""
        in_p = Path(input_path)
        out_p = Path(output_path)
        stats = SubsetStats(root_table=self.root_table)

        # Step 1: Infer FKs if none were explicitly registered
        if not self.downstream_fks:
            self.infer_foreign_keys_from_dump(in_p)

        # Pass 1: Collect root table keys and build initial reference graph
        self._pass1_collect_root_keys(in_p, stats)

        # Pass 2: Cascade and stream filtered dump to output
        out_p.parent.mkdir(parents=True, exist_ok=True)
        with (
            in_p.open("r", encoding="utf-8", errors="replace") as fin,
            out_p.open("w", encoding="utf-8") as fout,
        ):
            self._pass2_filter_stream(fin, fout, stats)

        return stats

    def _pass1_collect_root_keys(self, input_path: Path, stats: SubsetStats) -> None:
        """Pass 1: Identifies and collects the primary key values for the root table."""
        root_keys: set[str] = set()
        count = 0

        in_copy = False
        current_table = ""
        current_columns: list[str] = []

        with input_path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                stripped = line.strip()

                if in_copy:
                    if stripped == r"\.":
                        in_copy = False
                        continue
                    if current_table == self.root_table:
                        cells = line.rstrip("\n").split("\t")
                        if self.pk_column in current_columns:
                            pk_idx = current_columns.index(self.pk_column)
                            if pk_idx < len(cells):
                                root_keys.add(cells[pk_idx].strip())
                                count += 1
                                if count >= self.limit:
                                    break
                    continue

                copy_match = _COPY_PATTERN.match(line)
                if copy_match:
                    tbl = _clean_identifier(copy_match.group("table")).lower()
                    current_table = tbl
                    cols_str = copy_match.group("columns")
                    current_columns = (
                        [c.lower() for c in _parse_column_list(cols_str)] if cols_str else ["id"]
                    )
                    in_copy = True
                    continue

                insert_match = _INSERT_HEADER_PATTERN.match(line)
                if insert_match:
                    full_line = _read_full_insert(line, f)
                    tbl = _clean_identifier(insert_match.group("table")).lower()
                    if tbl == self.root_table:
                        cols_str = insert_match.group("columns")
                        cols = (
                            [c.lower() for c in _parse_column_list(cols_str)]
                            if cols_str
                            else ["id"]
                        )
                        raw_values = full_line[insert_match.end() :]
                        tuples = _split_multiple_tuples(raw_values)
                        for _, _, tup_str in tuples:
                            row_tokens = [
                                tok.strip() for _, _, tok in _split_sql_values_row(tup_str)
                            ]
                            if self.pk_column in cols:
                                pk_idx = cols.index(self.pk_column)
                                if pk_idx < len(row_tokens):
                                    parsed = _parse_sql_value(row_tokens[pk_idx])
                                    if parsed is not None:
                                        root_keys.add(str(parsed))
                                        count += 1
                                        if count >= self.limit:
                                            break
                        if count >= self.limit:
                            break

        self.kept_keys[self.root_table] = root_keys

    def _should_keep_row(self, table_name: str, columns: list[str], row_values: list[Any]) -> bool:
        """Determines whether a row in table_name satisfies referential constraints."""
        tbl = table_name.lower()
        cols_lower = [c.lower() for c in columns]

        # Case A: Root table - keep if PK is in kept_keys
        if tbl == self.root_table:
            if self.pk_column in cols_lower:
                idx = cols_lower.index(self.pk_column)
                if idx < len(row_values):
                    val_str = str(row_values[idx]).strip("'\"")
                    return val_str in self.kept_keys.get(self.root_table, set())
            return True

        # Case B: Child table referencing a kept parent table
        if tbl in self.downstream_fks:
            for child_col, parent_tbl, _parent_col in self.downstream_fks[tbl]:
                if child_col in cols_lower and parent_tbl in self.kept_keys:
                    idx = cols_lower.index(child_col)
                    if idx < len(row_values):
                        fk_val = str(row_values[idx]).strip("'\"")
                        if fk_val in self.kept_keys[parent_tbl]:
                            # Keep and track this child's own PK if present
                            if "id" in cols_lower:
                                id_idx = cols_lower.index("id")
                                if id_idx < len(row_values):
                                    if tbl not in self.kept_keys:
                                        self.kept_keys[tbl] = set()
                                    self.kept_keys[tbl].add(str(row_values[id_idx]).strip("'\""))
                            return True
                        else:
                            return False

        # Case C: Lookup / independent tables (keep all by default)
        return True

    def _pass2_filter_stream(self, fin: TextIO, fout: TextIO, stats: SubsetStats) -> None:
        """Pass 2: Streams SQL statements, filtering rows that violate subset constraints."""
        in_copy = False
        current_table = ""
        current_columns: list[str] = []

        for line in fin:
            stripped = line.strip()

            if in_copy:
                if stripped == r"\.":
                    in_copy = False
                    fout.write(line)
                    continue

                stats.total_rows_read += 1
                stats.rows_in_per_table[current_table] = (
                    stats.rows_in_per_table.get(current_table, 0) + 1
                )

                cells = line.rstrip("\n").split("\t")
                if self._should_keep_row(current_table, current_columns, cells):
                    stats.total_rows_written += 1
                    stats.rows_out_per_table[current_table] = (
                        stats.rows_out_per_table.get(current_table, 0) + 1
                    )
                    fout.write(line)
                continue

            copy_match = _COPY_PATTERN.match(line)
            if copy_match:
                tbl = _clean_identifier(copy_match.group("table")).lower()
                current_table = tbl
                cols_str = copy_match.group("columns")
                current_columns = (
                    [c.lower() for c in _parse_column_list(cols_str)] if cols_str else ["id"]
                )
                in_copy = True
                fout.write(line)
                continue

            insert_match = _INSERT_HEADER_PATTERN.match(line)
            if insert_match:
                full_line = _read_full_insert(line, fin)
                tbl = _clean_identifier(insert_match.group("table")).lower()
                cols_str = insert_match.group("columns")
                cols = [c.lower() for c in _parse_column_list(cols_str)] if cols_str else ["id"]

                raw_values = full_line[insert_match.end() :]
                tuples = _split_multiple_tuples(raw_values)
                kept_tuples: list[str] = []

                for _, _, tup_str in tuples:
                    stats.total_rows_read += 1
                    stats.rows_in_per_table[tbl] = stats.rows_in_per_table.get(tbl, 0) + 1

                    row_tokens = [tok.strip() for _, _, tok in _split_sql_values_row(tup_str)]
                    parsed_vals = [_parse_sql_value(v) for v in row_tokens]

                    if self._should_keep_row(tbl, cols, parsed_vals):
                        stats.total_rows_written += 1
                        stats.rows_out_per_table[tbl] = stats.rows_out_per_table.get(tbl, 0) + 1
                        kept_tuples.append(tup_str)

                if kept_tuples:
                    header = full_line[: insert_match.end()]
                    tail = ";\n" if full_line.rstrip().endswith(";") else "\n"
                    fout.write(f"{header}\n  " + ",\n  ".join(kept_tuples) + tail)
                continue

            # Pass through all DDL, comments, schema definitions unaltered
            fout.write(line)
