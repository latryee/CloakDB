"""Tests for Apache Parquet stream parsing and PII scanning."""

from __future__ import annotations

from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from cloakdb.config.models import CloakConfig, ColumnRule, GlobalConfig, TableRule
from cloakdb.core.engine import CloakEngine
from cloakdb.parsers.parquet_stream import ParquetStreamParser
from cloakdb.scanner.generator import ConfigGenerator


def create_sample_parquet(path: Path, num_rows: int = 100) -> None:
    """Helper creating a multi-column sample Parquet file."""
    ids = list(range(1, num_rows + 1))
    names = [f"User {i}" for i in range(1, num_rows + 1)]
    emails = [f"user{i}@corp.com" for i in range(1, num_rows + 1)]
    salaries = [50000.0 + (i * 100) for i in range(1, num_rows + 1)]

    table = pa.Table.from_pydict(
        {
            "id": ids,
            "full_name": names,
            "email": emails,
            "salary": salaries,
        }
    )
    pq.write_table(table, str(path), row_group_size=25)


def test_parquet_stream_parser(tmp_path: Path):
    """Verify ParquetStreamParser masks dataset while preserving columns and row count."""
    in_parquet = tmp_path / "raw_data.parquet"
    out_parquet = tmp_path / "masked_data.parquet"

    create_sample_parquet(in_parquet, num_rows=50)

    config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt="test-parquet-salt-1234567890123456"),
        tables={
            "raw_data": TableRule(
                columns={
                    "full_name": ColumnRule(
                        strategy="constant", params={"value_to_set": "ANONYMIZED"}
                    ),
                    "email": ColumnRule(
                        strategy="constant", params={"value_to_set": "masked@corp.com"}
                    ),
                }
            )
        },
    )

    engine = CloakEngine(config)
    parser = ParquetStreamParser(table_name="raw_data", batch_size=20)
    parser.process_file_chunked(in_parquet, out_parquet, engine)

    # Validate output Parquet file
    assert out_parquet.exists()
    out_table = pq.read_table(str(out_parquet))
    assert out_table.num_rows == 50
    assert set(out_table.column_names) == {"id", "full_name", "email", "salary"}

    names_list = out_table.column("full_name").to_pylist()
    emails_list = out_table.column("email").to_pylist()

    assert all(n == "ANONYMIZED" for n in names_list)
    assert all(e == "masked@corp.com" for e in emails_list)


def test_parquet_scanner_detection(tmp_path: Path):
    """Verify ConfigGenerator.scan_parquet correctly extracts columns and detects PII."""
    in_parquet = tmp_path / "customers.parquet"
    create_sample_parquet(in_parquet, num_rows=20)

    generator = ConfigGenerator()
    detections = generator.scan_parquet(in_parquet)

    assert "customers" in detections
    detected_cols = {d.column_name: d.pii_type for d in detections["customers"]}
    assert "email" in detected_cols
