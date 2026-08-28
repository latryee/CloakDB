"""Comprehensive test suite for Format-Preserving Encryption (FPE) strategies."""

import pytest

from cloakdb.core.context import TransformationContext
from cloakdb.strategies.fpe import (
    FeistelFPE,
    FPECreditCardStrategy,
    FPEEmailStrategy,
    FPENationalIDStrategy,
    FPEPhoneNumberStrategy,
    FPEStrategy,
)


def _make_context(salt: str = "test-salt-64-character-cryptographic-string-padding-ok", table: str = "users", column: str = "test_col") -> TransformationContext:
    return TransformationContext(
        table_name=table,
        column_name=column,
        row_index=0,
        salt=salt,
    )


def test_feistel_fpe_basic_and_lengths():
    key = b"12345678901234567890123456789012"
    fpe = FeistelFPE(key, alphabet="0123456789", rounds=6)

    # Test short and single char edge cases
    assert fpe.encrypt("") == ""
    single = fpe.encrypt("5", tweak=b"twk")
    assert len(single) == 1 and single in "0123456789"

    # Test multi-digit string
    pt = "1234567890123456"
    ct = fpe.encrypt(pt, tweak=b"test")
    assert len(ct) == len(pt)
    assert ct != pt
    assert all(c in "0123456789" for c in ct)

    # Test deterministic property
    ct2 = fpe.encrypt(pt, tweak=b"test")
    assert ct == ct2

    # Different tweak produces different ciphertext
    ct_diff = fpe.encrypt(pt, tweak=b"other")
    assert ct_diff != ct


def test_feistel_invalid_alphabet():
    with pytest.raises(ValueError, match="at least 2 characters"):
        FeistelFPE(b"key", alphabet="1")


def test_fpe_general_strategy():
    ctx = _make_context()
    strat = FPEStrategy()

    assert strat.transform(None, ctx) is None
    assert strat.transform("", ctx) == ""

    # Digits with formatting preserved
    res = strat.transform("123-456-789", ctx, alphabet="0123456789", preserve_format=True)
    assert len(res) == 11
    assert res[3] == "-" and res[7] == "-"
    assert res != "123-456-789"

    # Hex radix
    hex_res = strat.transform("deadbeef", ctx, radix=16)
    assert len(hex_res) == 8
    assert all(c in "0123456789abcdef" for c in hex_res)

    # Radix 36 and 62
    r36 = strat.transform("abc123xyz", ctx, radix=36)
    assert len(r36) == 9
    r62 = strat.transform("Abc123XyZ", ctx, radix=62)
    assert len(r62) == 9

    # Non-preserving format
    raw_enc = strat.transform("123456", ctx, radix=10, preserve_format=False)
    assert len(raw_enc) == 6


def test_fpe_credit_card_luhn_validity():
    ctx = _make_context()
    strat = FPECreditCardStrategy()

    assert strat.transform(None, ctx) is None

    # Test with standard 16-digit Visa card
    visa = "4532-1234-5678-9010"
    masked_visa = strat.transform(visa, ctx, preserve_prefix_len=1, luhn_checksum=True)

    assert masked_visa.startswith("4")
    assert len(masked_visa) == len(visa)
    assert masked_visa[4] == "-" and masked_visa[9] == "-" and masked_visa[14] == "-"
    assert masked_visa != visa

    # Verify Luhn validity of masked card
    digits = [int(c) for c in masked_visa if c.isdigit()]
    checksum = 0
    for i, d in enumerate(digits[::-1]):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    assert checksum % 10 == 0

    # Short card fallback
    short_val = "12345"
    res_short = strat.transform(short_val, ctx)
    assert len(res_short) == 5

    # Non-luhn and no-delimiter options
    masked_no_luhn = strat.transform("4532123456789010", ctx, luhn_checksum=False, preserve_delimiters=False)
    assert len(masked_no_luhn) == 16


def test_fpe_phone_number_strategy():
    ctx = _make_context()
    strat = FPEPhoneNumberStrategy()

    assert strat.transform(None, ctx) is None
    assert strat.transform("12", ctx) == "12"

    phone = "+1 (555) 234-5678"
    masked = strat.transform(phone, ctx, preserve_country_code=True)
    assert masked.startswith("+1")
    assert len(masked) == len(phone)
    assert "(" in masked and ")" in masked and "-" in masked
    assert masked != phone

    # Custom prefix digits
    int_phone = "00905551234567"
    masked_int = strat.transform(int_phone, ctx, preserve_prefix_digits=4)
    assert masked_int.startswith("0090")
    assert len(masked_int) == len(int_phone)


def test_fpe_national_id_strategy():
    ctx = _make_context()
    strat = FPENationalIDStrategy()

    assert strat.transform(None, ctx) is None

    # Test US SSN
    ssn = "123-45-6789"
    masked_ssn = strat.transform(ssn, ctx, id_type="ssn")
    assert len(masked_ssn) == 11
    assert masked_ssn[3] == "-" and masked_ssn[6] == "-"
    assert masked_ssn != ssn

    # Test Turkish TCKN
    tckn = "10000000146"
    masked_tckn = strat.transform(tckn, ctx, id_type="tckn", validate_checksum=True)
    assert len(masked_tckn) == 11
    assert masked_tckn[0] != "0"
    # Verify TCKN checksum
    d = [int(c) for c in masked_tckn]
    odd_sum = d[0] + d[2] + d[4] + d[6] + d[8]
    even_sum = d[1] + d[3] + d[5] + d[7]
    d10 = ((odd_sum * 7) - even_sum) % 10
    d11 = sum(d[:10]) % 10
    assert d[9] == d10 and d[10] == d11


def test_fpe_email_strategy():
    ctx = _make_context()
    strat = FPEEmailStrategy()

    assert strat.transform(None, ctx) is None
    assert strat.transform("invalid-email", ctx) != ""

    email = "john.doe+work@enterprise.corp"
    masked = strat.transform(email, ctx, preserve_domain=True)
    assert masked.endswith("@enterprise.corp")
    assert "." in masked.split("@")[0] or "+" in masked.split("@")[0]
    assert masked != email

    # Replace domain mode
    masked_anon = strat.transform(email, ctx, preserve_domain=False)
    assert masked_anon.endswith("@example.com")
