"""Tests for ParallelStreamParser (multi-core chunk streaming)."""

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
from cloakdb.parsers.chunking import ParallelStreamParser
from cloakdb.parsers.sql_dump import SQLDumpStreamParser


def test_parallel_streaming_matches_sequential_output(postgres_dump_file: Path):
    config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(seed=1337, salt="parallel-test-salt"),
        consistency_groups=[
            ConsistencyGroup(
                name="user_ids",
                columns=["users.id", "orders.user_id"],
                strategy="deterministic_hash",
                params={"as_integer": True, "min_int": 10000, "max_int": 99999},
            )
        ],
        tables={
            "users": TableRule(
                columns={
                    "id": ColumnRule(strategy="deterministic_hash", consistency_group="user_ids"),
                    "email": ColumnRule(strategy="email_mask"),
                    "full_name": ColumnRule(
                        strategy="constant", params={"value_to_set": "MASKED USER"}
                    ),
                }
            ),
            "orders": TableRule(
                columns={
                    "user_id": ColumnRule(
                        strategy="deterministic_hash", consistency_group="user_ids"
                    ),
                    "shipping_address": ColumnRule(
                        strategy="constant", params={"value_to_set": "CONFIDENTIAL ADDRESS"}
                    ),
                }
            ),
        },
    )

    input_text = postgres_dump_file.read_text(encoding="utf-8")

    # 1. Sequential Run
    seq_engine = CloakEngine(config)
    seq_parser = SQLDumpStreamParser()
    seq_out = io.StringIO()
    seq_parser.process_stream(io.StringIO(input_text), seq_out, seq_engine)
    seq_result = seq_out.getvalue()

    # 2. Parallel Run with 2 workers
    par_engine = CloakEngine(config)
    par_parser = ParallelStreamParser(workers=2, chunk_lines=2)
    par_out = io.StringIO()
    par_parser.process_stream(io.StringIO(input_text), par_out, par_engine)
    par_result = par_out.getvalue()

    assert par_result == seq_result, (
        "Parallel streaming output must match sequential streaming output identically"
    )
    assert par_engine.stats.rows_processed == seq_engine.stats.rows_processed
