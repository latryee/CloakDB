"""Tests for Differential Privacy masking strategy (Laplace and Gaussian mechanisms)."""

from __future__ import annotations

import pytest

from cloakdb.core.context import TransformationContext
from cloakdb.strategies.differential_privacy import DifferentialPrivacyStrategy


@pytest.fixture
def dp_ctx() -> TransformationContext:
    return TransformationContext(
        table_name="salaries",
        column_name="monthly_pay",
        row_index=1,
        salt="test-dp-salt-12345678901234567890",
        seed=42,
    )


def test_dp_laplace_mechanism_determinism(dp_ctx: TransformationContext):
    """Laplace mechanism should be deterministic when given identical salt and row context."""
    strat = DifferentialPrivacyStrategy()
    val = 50000.0

    res1 = strat.transform(val, dp_ctx, epsilon=0.5, sensitivity=1000.0, mechanism="laplace")
    res2 = strat.transform(val, dp_ctx, epsilon=0.5, sensitivity=1000.0, mechanism="laplace")

    assert res1 == res2
    assert isinstance(res1, float)
    # With sensitivity 1000 and epsilon 0.5, value should be perturbed
    assert res1 != val


def test_dp_gaussian_mechanism(dp_ctx: TransformationContext):
    """Gaussian mechanism should perturb value with (epsilon, delta) bounds."""
    strat = DifferentialPrivacyStrategy()
    val = 100.0

    res = strat.transform(
        val, dp_ctx, epsilon=1.0, sensitivity=5.0, mechanism="gaussian", delta=1e-4, decimals=2
    )

    assert isinstance(res, float)
    assert round(res, 2) == res
    assert res != val


def test_dp_bounds_clamping(dp_ctx: TransformationContext):
    """Differential privacy noise must respect min_val and max_val constraints."""
    strat = DifferentialPrivacyStrategy()
    val = 10.0

    res = strat.transform(
        val,
        dp_ctx,
        epsilon=0.01,  # huge noise scale
        sensitivity=10000.0,
        min_val=0.0,
        max_val=50.0,
    )

    assert 0.0 <= res <= 50.0


def test_dp_integer_preservation(dp_ctx: TransformationContext):
    """Differential privacy with integer values should return rounded integers."""
    strat = DifferentialPrivacyStrategy()
    val = 42

    res = strat.transform(val, dp_ctx, epsilon=1.0, sensitivity=10.0, as_integer=True)

    assert isinstance(res, int)


def test_dp_invalid_parameters(dp_ctx: TransformationContext):
    """Invalid epsilon, sensitivity, or delta should raise ValueError."""
    strat = DifferentialPrivacyStrategy()

    with pytest.raises(ValueError, match="epsilon must be > 0"):
        strat.transform(100.0, dp_ctx, epsilon=-1.0)

    with pytest.raises(ValueError, match="sensitivity must be > 0"):
        strat.transform(100.0, dp_ctx, sensitivity=0.0)

    with pytest.raises(ValueError, match="delta"):
        strat.transform(100.0, dp_ctx, mechanism="gaussian", delta=1.5)
