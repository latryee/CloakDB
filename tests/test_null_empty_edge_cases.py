"""Tests verifying robust, consistent handling of NULL, None, empty string, and whitespace inputs across all strategies."""

from __future__ import annotations

from typing import Any

import pytest

from cloakdb.core.context import TransformationContext
from cloakdb.strategies.registry import StrategyRegistry


@pytest.fixture
def dummy_context() -> TransformationContext:
    return TransformationContext(
        table_name="test_table",
        column_name="test_column",
        row_index=0,
        salt="0123456789abcdef0123456789abcdef",
        seed=42,
        locale="en_US",
    )


ALL_STRATEGY_NAMES = [
    "deterministic_hash",
    "uuid_hash",
    "faker",
    "pattern_mask",
    "email_mask",
    "credit_card_mask",
    "jitter",
    "range_random",
    "round_to",
    "date_shift",
    "date_truncate",
    "scramble",
    "choice",
    "tckn",
    "nullify",
    "constant",
    "regex_replace",
    "json_mask",
]


@pytest.mark.parametrize("strat_name", ALL_STRATEGY_NAMES)
def test_all_strategies_handle_null_gracefully(
    strat_name: str, dummy_context: TransformationContext
):
    """Every strategy must return None or appropriate default when given None without crashing."""
    strategy = StrategyRegistry.get(strat_name)

    extra_params: dict[str, Any] = {}
    if strat_name == "choice":
        extra_params = {"choices": ["A", "B", "C"]}
    elif strat_name == "json_mask":
        extra_params = {"rules": {"a": "constant"}}

    res = strategy.transform(None, dummy_context, **extra_params)
    assert res is None, f"Strategy {strat_name} failed to return None on NULL input"


@pytest.mark.parametrize("strat_name", ALL_STRATEGY_NAMES)
def test_all_strategies_handle_empty_string_gracefully(
    strat_name: str, dummy_context: TransformationContext
):
    """Every strategy must process an empty string '' without throwing exceptions."""
    strategy = StrategyRegistry.get(strat_name)

    extra_params: dict[str, Any] = {}
    if strat_name == "choice":
        extra_params = {"choices": ["A", "B"]}
    elif strat_name == "json_mask":
        extra_params = {"rules": {"a": "constant"}}

    # Should not raise exception
    res = strategy.transform("", dummy_context, **extra_params)
    assert res is not None or strat_name == "nullify"


@pytest.mark.parametrize("strat_name", ALL_STRATEGY_NAMES)
def test_all_strategies_handle_whitespace_string_gracefully(
    strat_name: str, dummy_context: TransformationContext
):
    """Every strategy must process whitespace '   ' without throwing exceptions."""
    strategy = StrategyRegistry.get(strat_name)

    extra_params: dict[str, Any] = {}
    if strat_name == "choice":
        extra_params = {"choices": ["A", "B"]}
    elif strat_name == "json_mask":
        extra_params = {"rules": {"a": "constant"}}

    res = strategy.transform("   ", dummy_context, **extra_params)
    assert res is not None or strat_name == "nullify"


def test_numeric_type_preservation(dummy_context: TransformationContext):
    """Numeric strategies must preserve input types (int -> int, float -> float)."""
    jitter = StrategyRegistry.get("jitter")
    round_to = StrategyRegistry.get("round_to")

    # Integer in -> Integer out
    res_int = jitter.transform(100, dummy_context, percentage=10.0)
    assert isinstance(res_int, int)

    res_round_int = round_to.transform(1234, dummy_context, step=10)
    assert isinstance(res_round_int, int)

    # Float in -> Float out
    res_float = jitter.transform(99.95, dummy_context, percentage=5.0, decimals=2)
    assert isinstance(res_float, float)

    res_round_float = round_to.transform(45.67, dummy_context, step=5.0)
    assert isinstance(res_round_float, float)
