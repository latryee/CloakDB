"""Test suite for OpenTelemetry telemetry, structured logging, and signed SOC2 audit trails."""

import io
import json
import logging
from pathlib import Path

from cloakdb.config.models import CloakConfig, GlobalConfig, TableRule
from cloakdb.core.context import MaskingStats
from cloakdb.observability.audit import generate_audit_log, verify_audit_log
from cloakdb.observability.telemetry import CloakTelemetry, setup_structured_logging


def test_telemetry_span_fallback_and_metrics():
    # Test initialization when OTel disabled or unavailable
    CloakTelemetry.initialize(enabled=False)
    with CloakTelemetry.span("test.span", {"key": "val"}) as span:
        span.set_attribute("attr", "123")
        span.set_status("OK")

    CloakTelemetry.record_metric("rows_masked", 500, labels={"table": "users"})
    assert CloakTelemetry._metrics.get("rows_masked:{'table': 'users'}") == 500


def test_structured_json_logging():
    stream = io.StringIO()
    setup_structured_logging(level=logging.INFO, stream=stream)

    logger = logging.getLogger("cloakdb.test")
    logger.info("Anonymization batch complete")

    output = stream.getvalue().strip()
    data = json.loads(output)
    assert data["level"] == "INFO"
    assert data["message"] == "Anonymization batch complete"
    assert "timestamp" in data


def test_generate_and_verify_audit_log(tmp_path: Path):
    salt = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    cfg = CloakConfig(
        version="1",
        global_settings=GlobalConfig(salt=salt),
        tables={"users": TableRule(columns={})},
    )
    stats = MaskingStats(
        tables_processed=1,
        rows_processed=1000,
        cells_masked=5000,
        bytes_processed=102400,
    )
    stats.record_privacy_budget(epsilon=0.5, delta=1e-5)

    audit_doc = generate_audit_log(
        config=cfg,
        stats=stats,
        input_target="postgresql://app_user:secret@prod-db.internal:5432/main",
        output_target="dump_clean.sql",
        signer_key=salt,
        actor="devops-ci",
    )

    assert "audit_payload" in audit_doc
    assert "integrity_signature" in audit_doc
    assert audit_doc["audit_payload"]["actor"] == "devops-ci"
    assert "secret" not in audit_doc["audit_payload"]["input_target"]
    assert audit_doc["audit_payload"]["privacy_budget_consumed"]["epsilon_total"] == 0.5

    # Verification with matching key
    is_valid, msg = verify_audit_log(audit_doc, signer_key=salt)
    assert is_valid is True
    assert "verified" in msg.lower()

    # File verification
    log_file = tmp_path / "audit.json"
    with open(log_file, "w", encoding="utf-8") as f:
        json.dump(audit_doc, f)

    is_valid_file, _ = verify_audit_log(log_file, signer_key=salt)
    assert is_valid_file is True

    # Verification with wrong key
    is_valid_bad_key, _ = verify_audit_log(audit_doc, signer_key="wrong-salt-key")
    assert is_valid_bad_key is False

    # Verification after tampering
    tampered_doc = json.loads(json.dumps(audit_doc))
    tampered_doc["audit_payload"]["metrics"]["rows_processed"] = 999999
    is_valid_tampered, _ = verify_audit_log(tampered_doc, signer_key=salt)
    assert is_valid_tampered is False

    # Malformed audit doc
    assert verify_audit_log({}, signer_key=salt)[0] is False
    assert verify_audit_log({"audit_payload": {}}, signer_key=salt)[0] is False
    assert verify_audit_log(tmp_path / "nonexistent.json", signer_key=salt)[0] is False
