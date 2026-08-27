"""Golden fixture integration tests verifying end-to-end SQL anonymization."""

import io
from pathlib import Path

from cloakdb.config.models import (
    CloakConfig,
    ColumnRule,
    ConsistencyGroup,
    GlobalConfig,
    TableRule,
)
from cloakdb.core.engine import CloakEngine
from cloakdb.parsers.sql_dump import SQLDumpStreamParser


def test_ecommerce_golden_fixture():
    fixtures_dir = Path(__file__).parent / "fixtures"
    input_file = fixtures_dir / "input_ecommerce.sql"
    expected_file = fixtures_dir / "expected_masked_ecommerce.sql"

    assert input_file.exists(), f"Missing fixture: {input_file}"
    assert expected_file.exists(), f"Missing fixture: {expected_file}"

    config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(seed=42, salt="fixture-salt-v1", locale="en_US"),
        consistency_groups=[
            ConsistencyGroup(
                name="cust_ids",
                strategy="deterministic_hash",
                params={"as_integer": True, "min_int": 20000, "max_int": 29999},
                columns=["customers.id", "orders.customer_id"],
            )
        ],
        tables={
            "customers": TableRule(
                columns={
                    "id": ColumnRule(strategy="deterministic_hash", consistency_group="cust_ids"),
                    "full_name": ColumnRule(
                        strategy="faker", params={"provider": "name", "deterministic": True}
                    ),
                    "email": ColumnRule(
                        strategy="faker", params={"provider": "email", "preserve_domain": True}
                    ),
                    "phone": ColumnRule(
                        strategy="pattern_mask",
                        params={"keep_first": 3, "keep_last": 4, "mask_char": "*"},
                    ),
                    "ssn": ColumnRule(
                        strategy="pattern_mask",
                        params={"keep_first": 0, "keep_last": 4, "mask_char": "*"},
                    ),
                    "salary": ColumnRule(strategy="constant", params={"value_to_set": 0.0}),
                }
            ),
            "orders": TableRule(
                columns={
                    "customer_id": ColumnRule(
                        strategy="deterministic_hash", consistency_group="cust_ids"
                    ),
                    "shipping_city": ColumnRule(
                        strategy="constant", params={"value_to_set": "CONFIDENTIAL"}
                    ),
                }
            ),
            "secret_tokens": TableRule(truncate=True),
        },
    )

    engine = CloakEngine(config)
    parser = SQLDumpStreamParser()

    input_sql = input_file.read_text(encoding="utf-8")
    expected_sql = expected_file.read_text(encoding="utf-8").strip()

    in_stream = io.StringIO(input_sql)
    out_stream = io.StringIO()

    parser.process_stream(in_stream, out_stream, engine)
    actual_output = out_stream.getvalue().strip()

    assert actual_output == expected_sql
