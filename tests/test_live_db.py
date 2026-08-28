"""Tests for LiveDatabaseConnector with SQLite."""

from pathlib import Path

import pytest
from sqlalchemy import (
    Column,
    Float,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
    insert,
    select,
)

from cloakdb.config.models import CloakConfig, ColumnRule, GlobalConfig, TableRule
from cloakdb.connectors.live_db import LiveDatabaseConnector
from cloakdb.core.engine import CloakEngine


def test_live_db_masking(tmp_path: Path):
    db_file = tmp_path / "test.db"
    db_url = f"sqlite:///{db_file}"

    engine = create_engine(db_url)
    metadata = MetaData()

    users_tbl = Table(
        "users",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("email", String),
        Column("full_name", String),
        Column("salary", Float),
    )
    metadata.create_all(engine)

    # Insert sample rows
    with engine.connect() as conn:
        conn.execute(
            insert(users_tbl),
            [
                {
                    "id": 1,
                    "email": "alice@test.com",
                    "full_name": "Alice Wonderland",
                    "salary": 100000.0,
                },
                {"id": 2, "email": "bob@test.com", "full_name": "Bob Builder", "salary": 80000.0},
            ],
        )
        conn.commit()

    config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt="live-db-test-salt"),
        tables={
            "users": TableRule(
                columns={
                    "email": ColumnRule(strategy="email_mask"),
                    "full_name": ColumnRule(
                        strategy="constant", params={"value_to_set": "Redacted User"}
                    ),
                }
            )
        },
    )

    cloak_engine = CloakEngine(config)
    connector = LiveDatabaseConnector(db_url)

    # Test schema inspection
    tables = connector.get_table_names()
    assert "users" in tables
    cols = connector.get_table_columns("users")
    assert len(cols) == 4
    col_names = [c["name"] for c in cols]
    assert "email" in col_names

    affected = connector.mask_table("users", cloak_engine, batch_size=10)
    assert affected == 2

    # Query back
    with engine.connect() as conn:
        rows = list(conn.execute(select(users_tbl)))
        assert len(rows) == 2
        assert rows[0].full_name == "Redacted User"
        assert rows[1].full_name == "Redacted User"
        assert rows[0].email != "alice@test.com"
        assert "@test.com" in rows[0].email


def test_live_db_no_pk_error(tmp_path: Path):
    db_file = tmp_path / "nopk.db"
    db_url = f"sqlite:///{db_file}"

    engine = create_engine(db_url)
    metadata = MetaData()

    Table(
        "logs",
        metadata,
        Column("message", String),
    )
    metadata.create_all(engine)

    config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt="live-db-test-salt"),
        tables={
            "logs": TableRule(
                columns={"message": ColumnRule(strategy="constant", params={"value_to_set": "X"})}
            )
        },
    )
    cloak_engine = CloakEngine(config)
    connector = LiveDatabaseConnector(db_url)

    with pytest.raises(ValueError, match="does not have a primary key defined"):
        connector.mask_table("logs", cloak_engine)
