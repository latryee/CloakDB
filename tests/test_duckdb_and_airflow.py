"""Tests for DuckDB connector and Apache Airflow integration."""

from __future__ import annotations

from pathlib import Path

from cloakdb.connectors.duckdb_connector import DuckDBConnector
from cloakdb.integrations.airflow import CloakDBOperator


def test_duckdb_connector_basic():
    """Test DuckDBConnector initialization."""
    connector = DuckDBConnector(database_path=":memory:")
    assert connector.db_path == ":memory:"


def test_airflow_operator_execution(tmp_path: Path):
    """Test CloakDBOperator runs masking pipeline on CSV dataset."""
    config_file = tmp_path / "cloakdb.yaml"
    config_file.write_text(
        """version: "1"
global:
  salt: "c8f1e2d3b4a567890123456789abcdef0123456789abcdef0123456789abcdef"
  seed: 42
tables:
  users:
    columns:
      email:
        strategy: "pattern_mask"
        params:
          keep_first: 1
          keep_last: 1
""",
        encoding="utf-8",
    )

    in_csv = tmp_path / "users.csv"
    in_csv.write_text("id,email\n1,alice@example.com\n2,bob@domain.org\n", encoding="utf-8")

    out_csv = tmp_path / "users_masked.csv"

    operator = CloakDBOperator(
        task_id="test_masking_task",
        config_file=str(config_file),
        input_target=str(in_csv),
        output_target=str(out_csv),
        verify=False,
    )

    res = operator.execute()

    assert res["rows_processed"] == 2
    assert res["cells_masked"] == 2
    assert out_csv.exists()

    content = out_csv.read_text(encoding="utf-8")
    assert "alice@example.com" not in content
    assert "bob@domain.org" not in content
