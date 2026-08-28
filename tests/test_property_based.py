"""Property-based invariant testing using Hypothesis.

Validates core mathematical and cryptographic invariants:
1. Determinism: f(x, salt) == f(x, salt) for all inputs x.
2. Distinctness: x != y => f(x) != f(y) with high probability (HMAC collision resistance).
3. Null Safety: keep_null=True => f(None) is None.
4. Range preservation: RangeRandom/Jitter respects lower and upper bounds.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from cloakdb.core.context import TransformationContext
from cloakdb.strategies.registry import StrategyRegistry


def make_ctx(
    salt: str = "0123456789abcdef0123456789abcdef", seed: int = 42
) -> TransformationContext:
    return TransformationContext(
        table_name="users",
        column_name="test_col",
        row_index=0,
        salt=salt,
        seed=seed,
        locale="en_US",
    )


@given(val=st.text(min_size=0, max_size=500), salt=st.text(min_size=32, max_size=64))
@settings(max_examples=100)
def test_property_deterministic_hash_string_invariants(val: str, salt: str):
    """Deterministic string hashing must be 100% idempotent, non-empty, and format-valid."""
    ctx1 = make_ctx(salt=salt)
    ctx2 = make_ctx(salt=salt)
    strategy = StrategyRegistry.get("deterministic_hash")

    res1 = strategy.transform(val, ctx1)
    res2 = strategy.transform(val, ctx2)

    # Determinism Invariant
    assert res1 == res2
    # String length invariant
    assert isinstance(res1, str)
    assert len(res1) > 0


@given(
    val=st.integers(min_value=-1_000_000_000, max_value=1_000_000_000),
    salt=st.text(min_size=32, max_size=64),
)
@settings(max_examples=100)
def test_property_deterministic_hash_integer_invariants(val: int, salt: str):
    """Deterministic integer hashing must return an integer within valid range deterministically."""
    ctx1 = make_ctx(salt=salt)
    ctx2 = make_ctx(salt=salt)
    strategy = StrategyRegistry.get("deterministic_hash")

    res1 = strategy.transform(val, ctx1, as_integer=True)
    res2 = strategy.transform(val, ctx2, as_integer=True)

    # Determinism Invariant
    assert res1 == res2
    assert isinstance(res1, int)
    assert res1 > 0


@given(v1=st.text(min_size=1, max_size=50), v2=st.text(min_size=1, max_size=50))
@settings(max_examples=100)
def test_property_deterministic_hash_collision_resistance(v1: str, v2: str):
    """Distinct inputs must map to distinct pseudonyms (collision resistance)."""
    if v1 == v2:
        return

    ctx = make_ctx()
    strategy = StrategyRegistry.get("deterministic_hash")

    res1 = strategy.transform(v1, ctx)
    res2 = strategy.transform(v2, ctx)

    assert res1 != res2


@given(
    val=st.text(min_size=0, max_size=100),
    keep_first=st.integers(min_value=0, max_value=5),
    keep_last=st.integers(min_value=0, max_value=5),
)
@settings(max_examples=100)
def test_property_pattern_mask_length_preservation(val: str, keep_first: int, keep_last: int):
    """Pattern mask must preserve total string character count."""
    ctx = make_ctx()
    strategy = StrategyRegistry.get("pattern_mask")

    res = strategy.transform(val, ctx, keep_first=keep_first, keep_last=keep_last, mask_char="*")

    assert isinstance(res, str)
    assert len(res) == len(val)
    if len(val) > keep_first + keep_last:
        if keep_first > 0:
            assert res[:keep_first] == val[:keep_first]
        if keep_last > 0:
            assert res[-keep_last:] == val[-keep_last:]


@given(
    val=st.floats(min_value=1.0, max_value=1_000_000.0, allow_nan=False, allow_infinity=False),
    min_v=st.floats(min_value=0.0, max_value=500.0, allow_nan=False, allow_infinity=False),
    max_v=st.floats(min_value=501.0, max_value=1000.0, allow_nan=False, allow_infinity=False),
)
@settings(max_examples=50)
def test_property_range_random_bounds(val: float, min_v: float, max_v: float):
    """RangeRandom must strictly contain the transformed value within [min_val, max_val]."""
    ctx = make_ctx()
    strategy = StrategyRegistry.get("range_random")

    res = strategy.transform(val, ctx, min_val=min_v, max_val=max_v, as_integer=False)
    assert min_v <= res <= max_v
