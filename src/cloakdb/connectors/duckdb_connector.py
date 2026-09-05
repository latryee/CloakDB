"""DuckDB connector for inspecting and masking DuckDB tables and Parquet/Lakehouse views."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cloakdb.core.engine import CloakEngine


class DuckDBConnector:
    """Connects to DuckDB databases (.duckdb or in-memory) for high-performance sanitization."""

    def __init__(self, database_path: str | Path = ":memory:"):
        self.db_path = str(database_path)
        self._connection: Any = None

    @property
    def connection(self) -> Any:
        """Lazily connects to DuckDB."""
        if self._connection is None:
            try:
                import duckdb

                self._connection = duckdb.connect(database=self.db_path)
            except ImportError as e:
                raise RuntimeError(
                    "duckdb package is required to connect to DuckDB databases. "
                    "Install with `pip install duckdb`."
                ) from e
        return self._connection

    def get_table_names(self) -> list[str]:
        """Returns all user table names in the DuckDB database."""
        result = self.connection.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main'"
        ).fetchall()
        return [row[0] for row in result]

    def get_columns(self, table_name: str) -> list[str]:
        """Returns column names for a given table."""
        res = self.connection.execute(f"DESCRIBE {table_name}").fetchall()
        return [row[0] for row in res]

    def fetch_sample_rows(self, table_name: str, limit: int = 10) -> list[dict[str, Any]]:
        """Fetches sample rows from a table as dictionaries."""
        cols = self.get_columns(table_name)
        rows = self.connection.execute(f"SELECT * FROM {table_name} LIMIT {limit}").fetchall()
        return [dict(zip(cols, row)) for row in rows]

    def mask_table_in_place(
        self,
        table_name: str,
        engine: CloakEngine,
        batch_size: int = 5000,
    ) -> int:
        """Masks a DuckDB table in batches, updating records directly."""
        cols = self.get_columns(table_name)
        total_rows = self.connection.execute(f"SELECT count(*) FROM {table_name}").fetchone()[0]
        if total_rows == 0:
            return 0

        # Create temporary masked table
        temp_tbl = f"_cloakdb_{table_name}_masked"
        self.connection.execute(f"CREATE TABLE {temp_tbl} AS SELECT * FROM {table_name} WHERE 1=0")

        offset = 0
        while offset < total_rows:
            batch = self.connection.execute(
                f"SELECT * FROM {table_name} LIMIT {batch_size} OFFSET {offset}"
            ).fetchall()
            if not batch:
                break

            masked_rows = []
            for row in batch:
                row_dict = dict(zip(cols, row))
                masked_dict = engine.mask_record(table_name, row_dict)
                masked_rows.append([masked_dict[c] for c in cols])

            # Insert batch into temp table
            placeholders = ", ".join(["?"] * len(cols))
            self.connection.executemany(
                f"INSERT INTO {temp_tbl} VALUES ({placeholders})", masked_rows
            )
            offset += len(batch)

        # Atomically swap tables
        self.connection.execute(f"DROP TABLE {table_name}")
        self.connection.execute(f"ALTER TABLE {temp_tbl} RENAME TO {table_name}")
        return total_rows

    def close(self) -> None:
        """Closes the DuckDB connection."""
        if self._connection is not None:
            self._connection.close()
            self._connection = None
