"""Tests for PII detector and auto-config generator."""

from pathlib import Path

from cloakdb.scanner.detector import (
    PIIDetector,
    _shannon_entropy,
    _validate_iban,
    _validate_luhn,
    _validate_tckn,
)
from cloakdb.scanner.generator import ConfigGenerator


def test_validator_functions():
    assert _validate_luhn("4532015012345678") is False
    assert _validate_luhn("49927398716") is True
    assert _validate_tckn("10000000146") is True
    assert _validate_tckn("12345678901") is False
    assert _validate_iban("TR330006100519786457841326") is True
    assert _validate_iban("INVALID_IBAN") is False
    assert _shannon_entropy("") == 0.0
    assert _shannon_entropy("aaaaaa") == 0.0
    assert _shannon_entropy("aB3$kL9@zX7#mQ2!") > 3.5


def test_pii_detector_email_and_phone():
    detector = PIIDetector()
    emails = ["john.doe@gmail.com", "alice@company.com", "support@domain.org"]
    res = detector.detect_column("contact_email", emails)
    assert res is not None
    assert res.pii_type == "email"
    assert res.recommended_strategy == "faker"

    phones = ["+1-555-0199", "+1-555-0142", "+1-555-0188"]
    res_phone = detector.detect_column("mobile_number", phones)
    assert res_phone is not None
    assert res_phone.pii_type == "phone"


def test_pii_detector_patterns_and_entropy():
    detector = PIIDetector()

    # Credit card detection
    cards = ["378282246310005", "378282246310005"]
    res_cc = detector.detect_column("card_number", cards)
    assert res_cc is not None
    assert res_cc.pii_type == "credit_card"

    # TCKN detection
    tckns = ["10000000146", "10000000146"]
    res_tckn = detector.detect_column("identity_number", tckns)
    assert res_tckn is not None
    assert res_tckn.pii_type == "tckn"

    # IBAN detection
    ibans = ["TR330006100519786457841326", "TR330006100519786457841326"]
    res_iban = detector.detect_column("bank_account", ibans)
    assert res_iban is not None
    assert res_iban.pii_type == "iban"

    # Empty samples return None
    assert detector.detect_column("unknown_col", []) is None


def test_credit_card_negative_detection_reduces_false_positives():
    detector = PIIDetector()

    # 1. 16-digit internal IDs / timestamps that fail Luhn should NOT be detected as credit card
    non_cc_numbers = ["4532015012345678", "5123456789012345", "6011000000000001"]
    res = detector.detect_column("transaction_ref_id", non_cc_numbers)
    assert res is None or res.pii_type != "credit_card"

    # 2. 16-digit sequential IDs with non-card prefixes
    non_card_prefix = ["8912345678901234", "9876543210987654"]
    res_prefix = detector.detect_column("internal_order_id", non_card_prefix)
    assert res_prefix is None or res_prefix.pii_type != "credit_card"



def test_scanner_sql_dump(postgres_dump_file: Path):
    generator = ConfigGenerator()
    detections = generator.scan_sql_dump(postgres_dump_file)

    assert "users" in detections
    detected_col_names = [d.column_name for d in detections["users"]]
    assert "email" in detected_col_names
    assert "full_name" in detected_col_names
    assert "phone" in detected_col_names

    config = generator.generate_config_from_detections(detections, locale="en_US")
    assert "users" in config.tables
    assert "email" in config.tables["users"].columns


def test_scanner_csv(csv_file: Path):
    generator = ConfigGenerator()
    detections = generator.scan_csv(csv_file, table_name="customers")
    assert "customers" in detections
    cols = [d.column_name for d in detections["customers"]]
    assert "email" in cols


def test_turkish_column_detection():
    detector = PIIDetector()
    res_tckn = detector.detect_column("tc_kimlik_no", ["10000000146"])
    assert res_tckn is not None
    assert res_tckn.pii_type == "tckn"
    assert res_tckn.recommended_strategy == "tckn"

    res_eposta = detector.detect_column("eposta_adresi", ["ahmet@sirket.com.tr"])
    assert res_eposta is not None
    assert res_eposta.pii_type == "email"

    res_maas = detector.detect_column("aylik_maas", [45000.0])
    assert res_maas is not None
    assert res_maas.pii_type == "salary"
