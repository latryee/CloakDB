"""Unit tests for all masking strategies."""

from datetime import date, datetime

import pytest

from cloakdb.core.context import TransformationContext
from cloakdb.scanner.detector import _validate_tckn
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
    assert strat.transform(None, base_context) is None

    # Base64 and prefix/suffix
    b64 = strat.transform(
        "user", base_context, output_format="base64", prefix="pre_", suffix="_post"
    )
    assert b64.startswith("pre_")
    assert b64.endswith("_post")


def test_deterministic_hash_integer(base_context: TransformationContext):
    strat = StrategyRegistry.get("deterministic_hash")
    out1 = strat.transform(42, base_context, as_integer=True, min_int=1000, max_int=9999)
    out2 = strat.transform(42, base_context, as_integer=True, min_int=1000, max_int=9999)

    assert isinstance(out1, int)
    assert 1000 <= out1 <= 9999
    assert out1 == out2


def test_uuid_hash_strategy(base_context: TransformationContext):
    strat = StrategyRegistry.get("uuid_hash")
    uuid1 = strat.transform("user-12345", base_context)
    uuid2 = strat.transform("user-12345", base_context)
    uuid3 = strat.transform("user-67890", base_context)

    assert isinstance(uuid1, str)
    assert len(uuid1) == 36
    assert uuid1 == uuid2
    assert uuid1 != uuid3
    assert strat.transform(None, base_context) is None


def test_faker_strategy_providers(base_context: TransformationContext):
    strat = StrategyRegistry.get("faker")
    assert strat.transform(None, base_context) is None

    providers = [
        "name",
        "first_name",
        "last_name",
        "phone_number",
        "address",
        "street_address",
        "city",
        "country",
        "postcode",
        "company",
        "job",
        "credit_card",
        "ssn",
        "iban",
        "ipv4",
        "ipv6",
        "user_name",
        "url",
        "sentence",
        "paragraph",
        "date_of_birth",
    ]
    for prov in providers:
        res = strat.transform("sample_val", base_context, provider=prov, deterministic=True)
        assert res is not None and len(str(res)) > 0


def test_faker_email_preserve_domain(base_context: TransformationContext):
    strat = StrategyRegistry.get("faker")
    masked = strat.transform(
        "ceo@myenterprise.org", base_context, provider="email", preserve_domain=True
    )
    assert masked.endswith("@myenterprise.org")
    assert not masked.startswith("ceo@")


def test_pattern_mask(base_context: TransformationContext):
    strat = StrategyRegistry.get("pattern_mask")
    masked = strat.transform("123456789", base_context, keep_first=2, keep_last=2, mask_char="*")
    assert masked == "12*****89"
    assert strat.transform(None, base_context) is None

    # Short string
    assert strat.transform("ab", base_context, keep_first=2, keep_last=2) == "**"
    # Custom mask length
    assert (
        strat.transform("123456789", base_context, keep_first=1, keep_last=1, mask_length=3)
        == "1***9"
    )


def test_email_mask(base_context: TransformationContext):
    strat = StrategyRegistry.get("email_mask")
    masked = strat.transform("john.doe@example.com", base_context, keep_first=1, keep_last=1)
    assert masked.startswith("j")
    assert masked.endswith("@example.com")
    assert "doe" not in masked
    assert strat.transform(None, base_context) is None

    # Non-email input
    assert strat.transform("plain_text", base_context) == "**********"


def test_credit_card_mask(base_context: TransformationContext):
    strat = StrategyRegistry.get("credit_card_mask")
    masked = strat.transform("4532-0150-1234-5678", base_context)
    assert masked == "****-****-****-5678"
    assert strat.transform(None, base_context) is None

    # Short credit card
    assert strat.transform("123", base_context) == "***"


def test_jitter_strategy(base_context: TransformationContext):
    strat = StrategyRegistry.get("jitter")
    masked_int = strat.transform(100000, base_context, percentage=10.0, deterministic=True)
    assert isinstance(masked_int, int)
    assert 90000 <= masked_int <= 110000
    assert masked_int != 100000
    assert strat.transform(None, base_context) is None

    # Gaussian distribution with min/max bounds and decimals
    masked_float = strat.transform(
        100.0,
        base_context,
        distribution="gaussian",
        percentage=20.0,
        min_val=85.0,
        max_val=115.0,
        decimals=2,
    )
    assert 85.0 <= masked_float <= 115.0

    # Non-numeric fallback
    assert strat.transform("not-a-number", base_context) == "not-a-number"


def test_date_shift_strategy(base_context: TransformationContext):
    strat = StrategyRegistry.get("date_shift")
    shifted = strat.transform("2024-05-15", base_context, max_days_forward=10, max_days_backward=10)
    assert isinstance(shifted, str)
    assert shifted != "2024-05-15"
    assert shifted.startswith("2024-05")
    assert strat.transform(None, base_context) is None

    # With datetime objects
    dt = datetime(2024, 5, 15, 12, 0, 0)
    shifted_dt = strat.transform(dt, base_context, preserve_day_of_week=True)
    assert isinstance(shifted_dt, (datetime, date))

    # Non-date string fallback
    assert strat.transform("invalid-date-string", base_context) == "invalid-date-string"


def test_date_truncate_strategy(base_context: TransformationContext):
    strat = StrategyRegistry.get("date_truncate")
    truncated_year = strat.transform("2024-07-25", base_context, level="year")
    assert truncated_year == "2024-01-01"

    truncated_month = strat.transform("2024-07-25", base_context, level="month")
    assert truncated_month == "2024-07-01"

    assert strat.transform(None, base_context) is None
    assert strat.transform("not-a-date", base_context) == "not-a-date"


def test_tckn_strategy(base_context: TransformationContext):
    strat = StrategyRegistry.get("tckn")
    tckn_val = strat.transform("10000000146", base_context, deterministic=True)
    assert len(tckn_val) == 11
    assert _validate_tckn(tckn_val) is True
    assert strat.transform(None, base_context) is None


def test_nullify_strategy(base_context: TransformationContext):
    strat = StrategyRegistry.get("nullify")
    assert strat.transform("anything", base_context) is None


def test_constant_strategy(base_context: TransformationContext):
    strat = StrategyRegistry.get("constant")
    assert strat.transform("confidential", base_context, value_to_set="[REDACTED]") == "[REDACTED]"
    assert strat.transform(None, base_context, keep_null=True) is None
    assert strat.transform(None, base_context, keep_null=False, value_to_set="DEFAULT") == "DEFAULT"


def test_choice_strategy(base_context: TransformationContext):
    strat = StrategyRegistry.get("choice")
    choices = ["PENDING", "APPROVED", "REJECTED"]
    out = strat.transform("ARCHIVED", base_context, choices=choices)
    assert out in choices
    assert strat.transform(None, base_context) is None
    assert strat.transform("VAL", base_context, choices=None) == "VAL"


def test_scramble_strategy(base_context: TransformationContext):
    strat = StrategyRegistry.get("scramble")
    out = strat.transform("Abc-123", base_context, deterministic=True)
    assert len(out) == 7
    assert out[3] == "-"
    assert out[0].isupper()
    assert out[1].islower()
    assert out[4].isdigit()
    assert strat.transform(None, base_context) is None


def test_regex_replace_strategy(base_context: TransformationContext):
    strat = StrategyRegistry.get("regex_replace")
    out = strat.transform("Order #12345", base_context, pattern=r"\d+", replacement="XXXXX")
    assert out == "Order #XXXXX"
    assert strat.transform(None, base_context) is None


def test_range_random_strategy(base_context: TransformationContext):
    strat = StrategyRegistry.get("range_random")
    out = strat.transform(10, base_context, min_val=100, max_val=200, as_integer=True)
    assert isinstance(out, int)
    assert 100 <= out <= 200

    out_float = strat.transform(10, base_context, min_val=5.0, max_val=10.0, as_integer=False)
    assert isinstance(out_float, float)
    assert 5.0 <= out_float <= 10.0
    assert strat.transform(None, base_context) is None


def test_round_to_strategy(base_context: TransformationContext):
    strat = StrategyRegistry.get("round_to")
    out = strat.transform(1234, base_context, step=100)
    assert out == 1200
    assert strat.transform(None, base_context) is None
    assert strat.transform("non-num", base_context) == "non-num"


def test_registry_unknown_strategy_error():
    with pytest.raises(KeyError, match="Unknown masking strategy"):
        StrategyRegistry.get("non_existent_strategy_xyz")
