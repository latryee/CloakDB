"""Performance benchmark runner for CloakDB masking engine."""

from __future__ import annotations

import time
from typing import Any, Dict, List
from cloakdb.config.models import CloakConfig, ColumnRule, TableRule
from cloakdb.core.engine import CloakEngine


def run_benchmark(
    row_count: int = 50000,
    batch_size: int = 5000,
) -> Dict[str, Any]:
    """Runs high-throughput benchmark across diverse strategy workloads."""
    config = CloakConfig(
        version="1",
        tables={
            "bench_users": TableRule(
                columns={
                    "id": ColumnRule(strategy="deterministic_hash", params={"as_integer": True}),
                    "email": ColumnRule(strategy="email_mask"),
                    "full_name": ColumnRule(strategy="faker", params={"provider": "name", "deterministic": True}),
                    "ssn": ColumnRule(strategy="pattern_mask", params={"keep_first": 0, "keep_last": 4}),
                    "salary": ColumnRule(strategy="jitter", params={"percentage": 10.0}),
                    "created_at": ColumnRule(strategy="date_shift", params={"max_days_forward": 30}),
                    "secret_token": ColumnRule(strategy="deterministic_hash", params={"output_format": "hex", "length": 32}),
                }
            )
        },
    )

    engine = CloakEngine(config)

    # Generate sample test record
    sample_record = {
        "id": 104859,
        "email": "sarah.connor@cyberdyne.systems",
        "full_name": "Sarah Connor",
        "ssn": "123-45-6789",
        "salary": 125000.50,
        "created_at": "2024-03-15 14:30:00",
        "secret_token": "sk_live_99a8b7c6d5e4f3a2b1c0",
    }

    start = time.perf_counter()
    for i in range(row_count):
        _ = engine.mask_record("bench_users", sample_record, row_index=i)

    duration = max(0.0001, time.perf_counter() - start)
    stats = engine.finish()

    return {
        "row_count": row_count,
        "duration_seconds": duration,
        "rows_per_sec": row_count / duration,
        "cells_masked": stats.cells_masked,
        "cells_per_sec": stats.cells_masked / duration,
        "columns_per_row": len(sample_record),
    }
