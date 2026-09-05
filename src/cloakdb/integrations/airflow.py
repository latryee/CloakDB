"""Apache Airflow integration: CloakDBOperator for ETL and data masking pipelines."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

try:
    from airflow.models import BaseOperator
except ImportError:
    # Graceful fallback when Airflow is not installed in the current environment
    class BaseOperator:  # type: ignore[no-redef]
        """Fallback BaseOperator placeholder when Apache Airflow is not installed."""

        def __init__(self, task_id: str, **kwargs: Any):
            self.task_id = task_id


class CloakDBOperator(BaseOperator):
    """Airflow Operator to sanitize and anonymize database dumps or tables during ETL DAG runs."""

    template_fields = ("input_target", "output_target", "config_file")

    def __init__(
        self,
        config_file: str,
        input_target: str,
        output_target: str | None = None,
        salt: str | None = None,
        workers: int = 1,
        verify: bool = True,
        dry_run: bool = False,
        task_id: str = "cloakdb_mask",
        **kwargs: Any,
    ):
        super().__init__(task_id=task_id, **kwargs)
        self.config_file = config_file
        self.input_target = input_target
        self.output_target = output_target
        self.salt = salt
        self.workers = workers
        self.verify = verify
        self.dry_run = dry_run

    def execute(self, context: Any = None) -> dict[str, Any]:
        """Executes CloakDB masking workflow within an Airflow task execution context."""
        from cloakdb.config.loader import load_config
        from cloakdb.core.engine import CloakEngine
        from cloakdb.scanner.generator import ConfigGenerator

        if self.salt:
            os.environ["SECRET_SALT"] = self.salt

        cfg = load_config(self.config_file)
        if self.salt:
            cfg.global_settings.salt = self.salt

        engine = CloakEngine(cfg)

        # File stream execution
        in_p = Path(self.input_target)
        if not in_p.exists():
            raise FileNotFoundError(f"Input file '{self.input_target}' does not exist.")

        out_p = Path(self.output_target) if self.output_target else None
        if not self.dry_run and not out_p:
            raise ValueError("output_target must be specified when dry_run=False.")

        if in_p.suffix.lower() == ".csv":
            from cloakdb.parsers.csv_stream import CSVStreamParser

            first_tbl = list(cfg.tables.keys())[0] if cfg.tables else "default"
            parser = CSVStreamParser(table_name=first_tbl)
            with in_p.open("r", encoding="utf-8") as fin, out_p.open("w", encoding="utf-8") as fout:  # type: ignore[union-attr]
                parser.process_stream(fin, fout, engine)
        else:
            from cloakdb.parsers.sql_dump import SQLDumpStreamParser

            sql_parser = SQLDumpStreamParser()
            with in_p.open("r", encoding="utf-8") as fin, out_p.open("w", encoding="utf-8") as fout:  # type: ignore[union-attr]
                sql_parser.process_stream(fin, fout, engine)

        # Verification
        if self.verify and out_p and out_p.exists():
            generator = ConfigGenerator()
            if str(out_p).endswith(".csv"):
                detections = generator.scan_csv(str(out_p), max_rows=1000, data_only=True)
            else:
                detections = generator.scan_sql_dump(str(out_p), max_lines=1000, data_only=True)

            if detections:
                total_leaks = sum(len(items) for items in detections.values())
                raise ValueError(
                    f"CloakDB verification failed: {total_leaks} sensitive columns contain unmasked PII."
                )

        return {
            "rows_processed": engine.stats.rows_processed,
            "cells_masked": engine.stats.cells_masked,
            "output_path": str(out_p) if out_p else None,
            "verified": self.verify,
        }
