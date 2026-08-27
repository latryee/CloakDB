"""Tests for LiveDatabaseConnector with SQLite."""

from pathlib import Path
from sqlalchemy import Column, Float, Integer, MetaData, String, Table, create_engine, insert, select
from cloakdb.config.models import CloakConfig, ColumnRule, TableRule
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
                {"id": 1, "email": "alice@test.com", "full_name": "Alice Wonderland", "salary": 100000.0},
                {"id": 2, "email": "bob@test.com", "full_name": "Bob Builder", "salary": 80000.0},
            ],
        )
        conn.commit()

    config = CloakConfig(
        version="1",
        tables={
            "users": TableRule(
                columns={
                    "email": ColumnRule(strategy="email_mask"),
                    "full_name": ColumnRule(strategy="constant", params={"value_to_set": "Redacted User"}),
                }
            )
        },
    )

    cloak_engine = CloakEngine(config)
    connector = LiveDatabaseConnector(db_url)

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
