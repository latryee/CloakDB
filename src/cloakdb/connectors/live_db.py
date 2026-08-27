"""SQLAlchemy-based live database connector for Postgres, MySQL, SQLite, and MariaDB."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional
from sqlalchemy import MetaData, Table, create_engine, inspect, select, update
from sqlalchemy.engine import Engine
from cloakdb.connectors.base import BaseDatabaseConnector
from cloakdb.core.engine import CloakEngine


class LiveDatabaseConnector(BaseDatabaseConnector):
    """Connects to live SQL databases via SQLAlchemy for in-place masking or schema extraction."""

    def __init__(self, connection_url: str):
        self.connection_url = connection_url
        self.engine: Engine = create_engine(connection_url)
        self.metadata = MetaData()

    def get_table_names(self) -> List[str]:
        inspector = inspect(self.engine)
        return inspector.get_table_names()

    def get_table_columns(self, table_name: str) -> List[Dict[str, Any]]:
        inspector = inspect(self.engine)
        cols = inspector.get_columns(table_name)
        return [{"name": c["name"], "type": str(c["type"]), "nullable": c.get("nullable", True)} for c in cols]

    def get_primary_keys(self, table_name: str) -> List[str]:
        inspector = inspect(self.engine)
        pk = inspector.get_pk_constraint(table_name)
        return pk.get("constrained_columns", [])

    def fetch_sample_rows(self, table_name: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetches a sample of rows from a live table."""
        table = Table(table_name, self.metadata, autoload_with=self.engine)
        stmt = select(table).limit(limit)
        with self.engine.connect() as conn:
            result = conn.execute(stmt)
            return [dict(row._mapping) for row in result]

    def mask_table(
        self,
        table_name: str,
        engine: CloakEngine,
        batch_size: int = 5000,
        progress_callback: Optional[Callable[[int], None]] = None,
    ) -> int:
        """Applies masking rules directly to a table in the database using primary key matching."""
        table = Table(table_name, self.metadata, autoload_with=self.engine)
        pks = self.get_primary_keys(table_name)
        if not pks:
            raise ValueError(f"Table '{table_name}' does not have a primary key defined for in-place updates.")

        tbl_rule = engine.get_table_rule(table_name)
        if not tbl_rule or not tbl_rule.columns:
            return 0

        # Build select statement
        stmt = select(table)
        if tbl_rule.where_clause:
            from sqlalchemy import text
            stmt = stmt.where(text(tbl_rule.where_clause))

        total_rows = 0

        with self.engine.connect() as conn:
            with conn.begin():
                result = conn.execution_options(yield_per=batch_size).execute(stmt)
                batch = []

                for row in result:
                    row_dict = dict(row._mapping)
                    masked = engine.mask_record(table_name, row_dict, row_index=total_rows)

                    # Extract updated fields (excluding untouched ones)
                    update_dict = {}
                    for col_name in tbl_rule.columns.keys():
                        for k, v in masked.items():
                            if k.lower() == col_name.lower() and v != row_dict[k]:
                                update_dict[k] = v

                    if update_dict:
                        pk_filter = {pk: row_dict[pk] for pk in pks}
                        batch.append((pk_filter, update_dict))

                    total_rows += 1
                    if len(batch) >= batch_size:
                        self._flush_batch(conn, table, batch)
                        if progress_callback:
                            progress_callback(len(batch))
                        batch = []

                if batch:
                    self._flush_batch(conn, table, batch)
                    if progress_callback:
                        progress_callback(len(batch))

        return total_rows

    def _flush_batch(self, conn: Any, table: Table, batch: List[tuple]) -> None:
        for pk_filter, update_dict in batch:
            stmt = update(table)
            for pk_col, pk_val in pk_filter.items():
                stmt = stmt.where(getattr(table.c, pk_col) == pk_val)
            stmt = stmt.values(**update_dict)
            conn.execute(stmt)
