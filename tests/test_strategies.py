"""Unit tests for all masking strategies."""

import pytest
from cloakdb.core.context import TransformationContext
from cloakdb.scanner.detector import _validate_luhn, _validate_tckn
from cloakdb.strategies.registry import StrategyRegistry


@pytest.fixture
def base_context() -> TransformationContext:
    return TransformationContext(
        table_name="users",
        column_name="test_col",
        row_index=1,
        seed=1337,
        salt="test-secret-salt",
    )


def test_deterministic_hash_string(base_context: TransformationContext):
    strat = StrategyRegistry.get("deterministic_hash")
    out1 = strat.transform("john.doe@example.com", base_context, length=16)
    out2 = strat.transform("john.doe@example.com", base_context, length=16)
    out3 = strat.transform("other.user@example.com", base_context, length=16)

    assert isinstance(out1, str)
    assert len(out1) == 16
    assert out1 == out2, "Deterministic hash must be reproducible"
    assert out1 != out3, "Different inputs must produce different hashes"


def test_deterministic_hash_integer(base_context: TransformationContext):
    strat = StrategyRegistry.get("deterministic_hash")
    out1 = strat.transform(42, base_context, as_integer=True, min_int=1000, max_int=9999)
    out2 = strat.transform(42, base_context, as_integer=True, min_int=1000, max_int=9999)

    assert isinstance(out1, int)
    assert 1000 <= out1 <= 9999
    assert out1 == out2


def test_faker_strategy(base_context: TransformationContext):
    strat = StrategyRegistry.get("faker")
    name1 = strat.transform("John Doe", base_context, provider="name", deterministic=True)
    name2 = strat.transform("John Doe", base_context, provider="name", deterministic=True)
    name3 = strat.transform("Jane Smith", base_context, provider="name", deterministic=True)

    assert isinstance(name1, str)
    assert len(name1) > 2
    assert name1 == name2
    assert name1 != name3


def test_faker_email_preserve_domain(base_context: TransformationContext):
    strat = StrategyRegistry.get("faker")
    masked = strat.transform("ceo@myenterprise.org", base_context, provider="email", preserve_domain=True)
    assert masked.endswith("@myenterprise.org")
    assert not masked.startswith("ceo@")


def test_pattern_mask(base_context: TransformationContext):
    strat = StrategyRegistry.get("pattern_mask")
    masked = strat.transform("123456789", base_context, keep_first=2, keep_last=2, mask_char="*")
    assert masked == "12*****89"


def test_email_mask(base_context: TransformationContext):
    strat = StrategyRegistry.get("email_mask")
    masked = strat.transform("john.doe@example.com", base_context, keep_first=1, keep_last=1)
    assert masked.startswith("j")
    assert masked.endswith("@example.com")
    assert "doe" not in masked


def test_credit_card_mask(base_context: TransformationContext):
    strat = StrategyRegistry.get("credit_card_mask")
    masked = strat.transform("4532-0150-1234-5678", base_context)
    assert masked == "****-****-****-5678"


def test_jitter_strategy(base_context: TransformationContext):
    strat = StrategyRegistry.get("jitter")
    masked_int = strat.transform(100000, base_context, percentage=10.0, deterministic=True)
    assert isinstance(masked_int, int)
    assert 90000 <= masked_int <= 110000
    assert masked_int != 100000


def test_date_shift_strategy(base_context: TransformationContext):
    strat = StrategyRegistry.get("date_shift")
    shifted = strat.transform("2024-05-15", base_context, max_days_forward=10, max_days_backward=10)
    assert isinstance(shifted, str)
    assert shifted != "2024-05-15"
    assert shifted.startswith("2024-05")


def test_date_truncate_strategy(base_context: TransformationContext):
    strat = StrategyRegistry.get("date_truncate")
    truncated = strat.transform("2024-07-25", base_context, level="year")
    assert truncated == "2024-01-01"


def test_tckn_strategy(base_context: TransformationContext):
    strat = StrategyRegistry.get("tckn")
    tckn_val = strat.transform("10000000146", base_context, deterministic=True)
    assert len(tckn_val) == 11
    assert _validate_tckn(tckn_val) is True


def test_nullify_strategy(base_context: TransformationContext):
    strat = StrategyRegistry.get("nullify")
    assert strat.transform("anything", base_context) is None


def test_constant_strategy(base_context: TransformationContext):
    strat = StrategyRegistry.get("constant")
    assert strat.transform("confidential", base_context, value_to_set="[REDACTED]") == "[REDACTED]"


def test_choice_strategy(base_context: TransformationContext):
    strat = StrategyRegistry.get("choice")
    choices = ["PENDING", "APPROVED", "REJECTED"]
    out = strat.transform("ARCHIVED", base_context, choices=choices)
    assert out in choices
