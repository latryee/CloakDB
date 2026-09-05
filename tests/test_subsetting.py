"""Tests for referential data subsetting engine and CLI command."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from cloakdb.cli import app
from cloakdb.core.subset import RelationalSubsettingEngine

runner = CliRunner()

SAMPLE_RELATIONAL_SQL = """-- CloakDB Relational Schema
CREATE TABLE users (
    id INT PRIMARY KEY,
    name VARCHAR(100),
    email VARCHAR(100)
);

CREATE TABLE orders (
    id INT PRIMARY KEY,
    user_id INT,
    total_amount DECIMAL(10, 2),
    CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users (id)
);

INSERT INTO users (id, name, email) VALUES
(1, 'Alice', 'alice@example.com'),
(2, 'Bob', 'bob@example.com'),
(3, 'Charlie', 'charlie@example.com'),
(4, 'David', 'david@example.com');

INSERT INTO orders (id, user_id, total_amount) VALUES
(101, 1, 99.50),
(102, 1, 150.00),
(103, 2, 45.00),
(104, 3, 220.00),
(105, 4, 15.00),
(106, 4, 80.00);
"""


def test_relational_subsetting_engine(tmp_path: Path):
    """Test subsetting keeps relational foreign keys intact while reducing row counts."""
    dump_file = tmp_path / "full_dump.sql"
    dump_file.write_text(SAMPLE_RELATIONAL_SQL, encoding="utf-8")

    out_file = tmp_path / "subset_dump.sql"

    engine = RelationalSubsettingEngine(
        root_table="users",
        limit=2,  # Keep only users 1 and 2
        pk_column="id",
        foreign_keys=[("orders", "user_id", "users", "id")],
    )

    stats = engine.subset_sql_dump(dump_file, out_file)

    assert stats.rows_out_per_table["users"] == 2
    assert stats.rows_out_per_table["orders"] == 3  # Orders 101, 102 (user 1) and 103 (user 2)
    assert stats.reduction_percentage > 0

    content = out_file.read_text(encoding="utf-8")
    assert "CREATE TABLE users" in content
    assert "'Alice'" in content
    assert "'Bob'" in content
    assert "'Charlie'" not in content
    assert "'David'" not in content
    assert "101" in content
    assert "102" in content
    assert "103" in content
    assert "104" not in content  # Belongs to Charlie (user 3)
    assert "105" not in content  # Belongs to David (user 4)


def test_cli_subset_command(tmp_path: Path):
    """Test cloakdb subset CLI invocation."""
    dump_file = tmp_path / "db.sql"
    dump_file.write_text(SAMPLE_RELATIONAL_SQL, encoding="utf-8")
    out_file = tmp_path / "subset.sql"

    result = runner.invoke(
        app,
        ["subset", "-i", str(dump_file), "-o", str(out_file), "-t", "users", "-n", "1"],
    )

    assert result.exit_code == 0
    assert "Referential Data Subsetting" in result.output
    assert "SUBSETTING COMPLETE!" in result.output
    assert out_file.exists()
