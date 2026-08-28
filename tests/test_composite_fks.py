"""Tests for Composite Foreign Keys and automated FK schema inference (--infer-fks)."""

from __future__ import annotations

import secrets
from pathlib import Path

from typer.testing import CliRunner

from cloakdb.cli import app
from cloakdb.config.models import CloakConfig, ColumnRule, ConsistencyGroup, GlobalConfig, TableRule
from cloakdb.core.engine import CloakEngine
from cloakdb.scanner.generator import ConfigGenerator

runner = CliRunner()


def test_composite_foreign_key_referential_integrity():
    """Verify composite (multi-column) consistency groups produce identical tuples across tables."""
    salt = secrets.token_hex(32)
    config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(
            salt=salt,
            cache_pseudonyms=True,
        ),
        consistency_groups=[
            ConsistencyGroup(
                name="cg_tenant_user",
                columns=["orders.(tenant_id, user_id)", "audit_logs.(tenant_id, user_id)"],
                strategy="deterministic_hash",
            )
        ],
        tables={
            "orders": TableRule(
                columns={
                    "order_total": ColumnRule(strategy="constant", params={"value_to_set": 100})
                }
            ),
            "audit_logs": TableRule(
                columns={
                    "action": ColumnRule(strategy="constant", params={"value_to_set": "LOGIN"})
                }
            ),
        },
    )

    engine = CloakEngine(config)

    order_record_1 = {"tenant_id": 5, "user_id": 999, "order_total": 450}
    order_record_2 = {"tenant_id": 5, "user_id": 999, "order_total": 120}
    order_record_other = {"tenant_id": 6, "user_id": 999, "order_total": 300}

    audit_record_1 = {"tenant_id": 5, "user_id": 999, "action": "PURCHASE"}
    audit_record_other = {"tenant_id": 6, "user_id": 999, "action": "PURCHASE"}

    masked_order_1 = engine.mask_record("orders", order_record_1)
    masked_order_2 = engine.mask_record("orders", order_record_2)
    masked_order_other = engine.mask_record("orders", order_record_other)

    masked_audit_1 = engine.mask_record("audit_logs", audit_record_1)
    masked_audit_other = engine.mask_record("audit_logs", audit_record_other)

    # 1. Identical composite tuples in different tables map to identical masked tuples
    assert (masked_order_1["tenant_id"], masked_order_1["user_id"]) == (
        masked_audit_1["tenant_id"],
        masked_audit_1["user_id"],
    )

    # 2. Identical composite tuples in the same table map identically
    assert (masked_order_1["tenant_id"], masked_order_1["user_id"]) == (
        masked_order_2["tenant_id"],
        masked_order_2["user_id"],
    )

    # 3. Different composite tuples map to different masked tuples (tenant 5 vs tenant 6)
    assert (masked_order_1["tenant_id"], masked_order_1["user_id"]) != (
        masked_order_other["tenant_id"],
        masked_order_other["user_id"],
    )
    assert (masked_order_other["tenant_id"], masked_order_other["user_id"]) == (
        masked_audit_other["tenant_id"],
        masked_audit_other["user_id"],
    )


def test_infer_fks_from_sql_dump(tmp_path: Path):
    """Verify --infer-fks extracts single and composite foreign key relationships from SQL DDL."""
    dump_file = tmp_path / "schema.sql"
    dump_content = """
    CREATE TABLE users (
        id INT PRIMARY KEY,
        email VARCHAR(255)
    );

    CREATE TABLE orders (
        order_id INT PRIMARY KEY,
        customer_id INT REFERENCES users(id),
        order_date DATE
    );

    CREATE TABLE multi_tenant_orders (
        org_id INT,
        account_id INT,
        amount NUMERIC,
        PRIMARY KEY (org_id, account_id)
    );

    CREATE TABLE multi_tenant_items (
        item_id INT PRIMARY KEY,
        org_id INT,
        account_id INT,
        FOREIGN KEY (org_id, account_id) REFERENCES multi_tenant_orders (org_id, account_id)
    );

    ALTER TABLE ONLY orders ADD CONSTRAINT fk_user FOREIGN KEY (customer_id) REFERENCES users(id);
    """
    dump_file.write_text(dump_content, encoding="utf-8")

    generator = ConfigGenerator()
    inferred_groups = generator.infer_foreign_keys_sql_dump(dump_file)

    # Inferred groups should contain both single and composite relationships
    group_names = [g.name for g in inferred_groups]
    assert any("users_id" in g for g in group_names)
    assert any("composite_multi_tenant_orders" in g for g in group_names)

    # Generate config with infer_fks=True
    detections = generator.scan_sql_dump(dump_file)
    cfg = generator.generate_config_from_detections(
        detections, target=str(dump_file), infer_fks=True
    )

    assert len(cfg.consistency_groups) >= 2


def test_cli_scan_with_infer_fks_flag(tmp_path: Path):
    """Verify cloakdb scan --infer-fks CLI integration."""
    dump_file = tmp_path / "schema.sql"
    cfg_output = tmp_path / "inferred_cloakdb.yaml"
    dump_content = """
    CREATE TABLE users (
        id INT PRIMARY KEY,
        email VARCHAR(255)
    );
    CREATE TABLE orders (
        order_id INT PRIMARY KEY,
        user_id INT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    INSERT INTO users VALUES (1, 'john@example.com');
    INSERT INTO orders VALUES (101, 1);
    """
    dump_file.write_text(dump_content, encoding="utf-8")

    res = runner.invoke(app, ["scan", str(dump_file), "-o", str(cfg_output), "--infer-fks"])
    assert res.exit_code == 0
    assert cfg_output.exists()

    content = cfg_output.read_text(encoding="utf-8")
    assert "consistency_groups" in content
    assert "users.id" in content or "orders.user_id" in content
