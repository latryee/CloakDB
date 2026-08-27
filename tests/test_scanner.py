"""Tests for PII detector and auto-config generator."""

from pathlib import Path
from cloakdb.scanner.detector import PIIDetector, _validate_iban, _validate_luhn, _validate_tckn
from cloakdb.scanner.generator import ConfigGenerator


def test_validator_functions():
    assert _validate_luhn("4532015012345678") is False  # invalid sample
    assert _validate_luhn("49927398716") is True  # valid Luhn
    assert _validate_tckn("10000000146") is True  # valid TCKN
    assert _validate_tckn("12345678901") is False  # invalid TCKN
    assert _validate_iban("TR330006100519786457841326") is True  # valid IBAN


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


def test_scanner_sql_dump(postgres_dump_file: Path):
    generator = ConfigGenerator()
    detections = generator.scan_sql_dump(postgres_dump_file)

    assert "users" in detections
    detected_col_names = [d.column_name for d in detections["users"]]
    assert "email" in detected_col_names
    assert "full_name" in detected_col_names
    assert "phone" in detected_col_names


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

