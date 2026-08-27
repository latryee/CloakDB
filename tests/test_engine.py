"""Tests for CloakEngine, consistency groups, and referential integrity."""

from cloakdb.config.models import CloakConfig, ColumnRule, ConsistencyGroup, TableRule
from cloakdb.core.engine import CloakEngine


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
                    "user_id": ColumnRule(strategy="deterministic_hash", consistency_group="user_ids"),
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
    assert masked_user["id"] == masked_order["user_id"], "Foreign key must match primary key pseudonym"


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
