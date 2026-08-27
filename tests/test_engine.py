"""Tests for CloakEngine, consistency groups, and referential integrity."""

from cloakdb.config.models import CloakConfig, ColumnRule, ConsistencyGroup, TableRule
from cloakdb.core.engine import CloakEngine, evaluate_condition


def test_engine_referential_integrity():
    # users.id and orders.user_id belong to same consistency group
    config = CloakConfig(
        version="1",
        consistency_groups=[
            ConsistencyGroup(
                name="user_ids",
                columns=["users.id", "orders.user_id"],
                strategy="deterministic_hash",
                params={"as_integer": True, "min_int": 50000, "max_int": 99999},
            )
        ],
        tables={
            "users": TableRule(
                columns={
                    "id": ColumnRule(strategy="deterministic_hash", consistency_group="user_ids"),
                    "email": ColumnRule(strategy="email_mask"),
                }
            ),
            "orders": TableRule(
                columns={
                    "user_id": ColumnRule(
                        strategy="deterministic_hash", consistency_group="user_ids"
                    ),
                }
            ),
        },
    )

    engine = CloakEngine(config)

    # Mask user 42
    user_record = {"id": 42, "email": "alice@test.com"}
    masked_user = engine.mask_record("users", user_record)

    # Mask order for user 42
    order_record = {"order_id": 901, "user_id": 42, "amount": 100}
    masked_order = engine.mask_record("orders", order_record)

    assert masked_user["id"] != 42
    assert masked_order["user_id"] != 42
    assert masked_user["id"] == masked_order["user_id"], (
        "Foreign key must match primary key pseudonym"
    )


def test_engine_conditional_masking():
    config = CloakConfig(
        version="1",
        tables={
            "employees": TableRule(
                columns={
                    "salary": ColumnRule(
                        strategy="constant",
                        params={"value_to_set": 0},
                        condition="country == 'US'",  # only mask if US
                    )
                }
            )
        },
    )

    engine = CloakEngine(config)

    us_employee = {"id": 1, "country": "US", "salary": 120000}
    uk_employee = {"id": 2, "country": "UK", "salary": 95000}

    res_us = engine.mask_record("employees", us_employee)
    res_uk = engine.mask_record("employees", uk_employee)

    assert res_us["salary"] == 0
    assert res_uk["salary"] == 95000


def test_evaluate_condition_ast():
    row = {"status": "ACTIVE", "age": 25, "role": "admin", "score": 85.5}

    assert evaluate_condition("status == 'ACTIVE'", row) is True
    assert evaluate_condition("status != 'ACTIVE'", row) is False
    assert evaluate_condition("age >= 18 and role == 'admin'", row) is True
    assert evaluate_condition("age < 18 or role == 'guest'", row) is False
    assert evaluate_condition("not (age < 21)", row) is True
    assert evaluate_condition("status in ['ACTIVE', 'PENDING']", row) is True
    assert evaluate_condition("status not in ['BANNED', 'SUSPENDED']", row) is True
    assert evaluate_condition("age + 5 == 30", row) is True
    assert evaluate_condition("score - 5.5 == 80.0", row) is True
    assert evaluate_condition("", row) is True
    assert evaluate_condition("invalid syntax ??? !!!", row) is False
    assert evaluate_condition("().__class__.__bases__", row) is False


def test_engine_truncate_and_row_values():
    config = CloakConfig(
        version="1",
        tables={
            "logs": TableRule(truncate=True),
            "users": TableRule(
                columns={
                    "email": ColumnRule(strategy="constant", params={"value_to_set": "masked"})
                }
            ),
        },
    )
    engine = CloakEngine(config)

    assert engine.should_truncate_table("logs") is True
    assert engine.should_truncate_table("users") is False
    assert engine.should_truncate_table("nonexistent") is False

    row_vals = [1, "test@example.com", "other"]
    cols = ["id", "email", "notes"]
    masked = engine.mask_row_values("users", cols, row_vals)
    assert masked[1] == "masked"
    assert masked[0] == 1
    assert masked[2] == "other"

    # Unconfigured table returns unchanged row values
    unmasked = engine.mask_row_values("unknown_table", cols, row_vals)
    assert unmasked == row_vals


def test_deterministic_hash_across_tables_without_consistency_group():
    """Test A: deterministic_hash produces the same pseudonym across tables without a ConsistencyGroup."""
    config = CloakConfig(
        version="1",
        tables={
            "users": TableRule(
                columns={
                    "email": ColumnRule(
                        strategy="deterministic_hash", params={"output_format": "hex", "length": 16}
                    ),
                }
            ),
            "audit_logs": TableRule(
                columns={
                    "email": ColumnRule(
                        strategy="deterministic_hash", params={"output_format": "hex", "length": 16}
                    ),
                }
            ),
        },
    )

    engine = CloakEngine(config)
    user_rec = {"email": "alice@example.com"}
    audit_rec = {"email": "alice@example.com"}

    masked_user = engine.mask_record("users", user_rec)
    masked_audit = engine.mask_record("audit_logs", audit_rec)

    assert masked_user["email"] == masked_audit["email"], (
        "deterministic_hash must match across tables for identical raw values"
    )


def test_deterministic_hash_different_column_names():
    """Test B: deterministic_hash produces the same pseudonym across different column names."""
    config = CloakConfig(
        version="1",
        tables={
            "users": TableRule(
                columns={
                    "email": ColumnRule(
                        strategy="deterministic_hash", params={"output_format": "hex", "length": 16}
                    ),
                }
            ),
            "audit_logs": TableRule(
                columns={
                    "actor_email": ColumnRule(
                        strategy="deterministic_hash", params={"output_format": "hex", "length": 16}
                    ),
                }
            ),
        },
    )

    engine = CloakEngine(config)
    user_rec = {"email": "alice@example.com"}
    audit_rec = {"actor_email": "alice@example.com"}

    masked_user = engine.mask_record("users", user_rec)
    masked_audit = engine.mask_record("audit_logs", audit_rec)

    assert masked_user["email"] == masked_audit["actor_email"], (
        "deterministic_hash must match even under different column names"
    )


def test_faker_without_consistency_group_is_column_scoped():
    """Test C: Faker without a consistency group is table/column-scoped and does not accidentally match globally."""
    config = CloakConfig(
        version="1",
        tables={
            "users": TableRule(
                columns={
                    "email": ColumnRule(
                        strategy="faker", params={"provider": "email", "deterministic": True}
                    ),
                }
            ),
            "audit_logs": TableRule(
                columns={
                    "email": ColumnRule(
                        strategy="faker", params={"provider": "email", "deterministic": True}
                    ),
                }
            ),
        },
    )

    engine = CloakEngine(config)
    user_rec = {"email": "alice@example.com"}
    audit_rec = {"email": "alice@example.com"}

    masked_user = engine.mask_record("users", user_rec)
    masked_audit = engine.mask_record("audit_logs", audit_rec)

    # In un-grouped mode, Faker seeds include table_name, ensuring column/table isolation
    assert masked_user["email"] != masked_audit["email"], (
        "Un-grouped Faker should be table-scoped by default"
    )


def test_faker_with_consistency_group_matches_across_tables_and_columns():
    """Test D: Faker with a consistency group produces the exact same pseudonym across tables and column names."""
    config = CloakConfig(
        version="1",
        consistency_groups=[
            ConsistencyGroup(
                name="user_email_group",
                columns=["users.email", "audit_logs.actor_email"],
                strategy="faker",
                params={"provider": "email", "deterministic": True},
            )
        ],
        tables={
            "users": TableRule(
                columns={
                    "email": ColumnRule(strategy="faker", consistency_group="user_email_group"),
                }
            ),
            "audit_logs": TableRule(
                columns={
                    "actor_email": ColumnRule(
                        strategy="faker", consistency_group="user_email_group"
                    ),
                }
            ),
        },
    )

    engine = CloakEngine(config)
    user_rec = {"email": "alice@example.com"}
    audit_rec = {"actor_email": "alice@example.com"}

    masked_user = engine.mask_record("users", user_rec)
    masked_audit = engine.mask_record("audit_logs", audit_rec)

    assert masked_user["email"] == masked_audit["actor_email"], (
        "ConsistencyGroup Faker must produce identical pseudonyms"
    )


def test_consistency_group_after_cache_eviction():
    """Test E: Correctness does not depend on LRU cache retention; recomputing after eviction produces identical pseudonym."""
    config = CloakConfig(
        version="1",
        global_settings={
            "max_cache_size": 2,  # Very small cache to force eviction
            "cache_pseudonyms": True,
        },
        consistency_groups=[
            ConsistencyGroup(
                name="user_email_group",
                columns=["users.email", "audit_logs.actor_email"],
                strategy="faker",
                params={"provider": "email", "deterministic": True},
            )
        ],
        tables={
            "users": TableRule(
                columns={
                    "email": ColumnRule(strategy="faker", consistency_group="user_email_group"),
                }
            ),
            "audit_logs": TableRule(
                columns={
                    "actor_email": ColumnRule(
                        strategy="faker", consistency_group="user_email_group"
                    ),
                }
            ),
        },
    )

    engine = CloakEngine(config)

    # 1. Mask original value on users table
    first_masked = engine.mask_record("users", {"email": "alice@example.com"})["email"]

    # 2. Flood cache with unique values to guarantee eviction of "alice@example.com"
    for i in range(10):
        engine.mask_record("users", {"email": f"dummy_user_{i}@example.com"})

    # Verify that "alice@example.com" was indeed evicted from cache
    cache = engine.integrity_manager._group_caches.get("user_email_group")
    assert cache is not None
    assert not cache.contains("alice@example.com"), (
        "Original value must have been evicted from LRU cache"
    )

    # 3. Mask original value on a DIFFERENT table and DIFFERENT column name (audit_logs.actor_email)
    second_masked = engine.mask_record("audit_logs", {"actor_email": "alice@example.com"})[
        "actor_email"
    ]

    # 4. Assert that the re-computed value is mathematically identical
    assert first_masked == second_masked, (
        "Recomputed synthetic pseudonym after cache eviction must match first occurrence"
    )
