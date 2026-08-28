"""Tamper-evident, cryptographically signed audit trail logs for SOC2 & ISO 27001 compliance."""

from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cloakdb import __version__
from cloakdb.config.models import CloakConfig
from cloakdb.core.context import MaskingStats
from cloakdb.utils.security import redact_connection_url


def _canonical_json_bytes(data: dict[str, Any]) -> bytes:
    """Serializes a dictionary to canonical deterministic JSON bytes."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _compute_config_hash(config: CloakConfig, config_path: str | Path | None = None) -> str:
    """Computes SHA-256 hash of configuration contents or config file."""
    if config_path and Path(config_path).exists():
        with open(config_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    cfg_json = config.model_dump_json() if hasattr(config, "model_dump_json") else str(config)
    return hashlib.sha256(cfg_json.encode("utf-8")).hexdigest()


class AuditTrailManager:
    """Generates and cryptographically verifies tamper-evident audit logs."""

    @staticmethod
    def generate_audit_log(
        config: CloakConfig,
        stats: MaskingStats,
        input_target: str,
        output_target: str | None,
        config_path: str | Path | None = None,
        signer_key: str | None = None,
        actor: str | None = None,
    ) -> dict[str, Any]:
        """Generates a cryptographically signed audit log record."""
        current_user = (
            actor or os.getenv("CLOAKDB_ACTOR") or os.getenv("USER") or os.getenv("USERNAME")
        )
        if not current_user:
            try:
                current_user = getpass.getuser()
            except Exception:
                current_user = "anonymous"

        effective_key = signer_key or config.global_settings.salt or "cloakdb-audit-key"
        key_bytes = (
            effective_key.encode("utf-8") if isinstance(effective_key, str) else effective_key
        )

        timestamp_iso = datetime.now(timezone.utc).isoformat()
        cfg_hash = _compute_config_hash(config, config_path)

        payload: dict[str, Any] = {
            "schema_version": "1.0.0",
            "timestamp": timestamp_iso,
            "cloakdb_version": __version__,
            "actor": current_user,
            "host": platform.node(),
            "config_hash_sha256": cfg_hash,
            "salt_fingerprint": config.global_settings.salt_fingerprint
            or config.global_settings.compute_fingerprint(),
            "input_target": redact_connection_url(str(input_target)),
            "output_target": redact_connection_url(str(output_target))
            if output_target
            else "[Live In-Place / Stdout]",
            "metrics": {
                "tables_processed": stats.tables_processed,
                "rows_processed": stats.rows_processed,
                "cells_masked": stats.cells_masked,
                "bytes_processed": stats.bytes_processed,
                "elapsed_seconds": round(stats.elapsed_seconds, 4),
                "throughput_rows_per_sec": round(stats.rows_per_second, 2),
            },
            "privacy_budget_consumed": {
                "epsilon_total": stats.privacy_budget.get("epsilon_total", 0.0),
                "delta_total": stats.privacy_budget.get("delta_total", 0.0),
            },
            "compliance_tags": ["SOC2_CC6.1", "ISO27001_A.8.24", "GDPR_Art32_Pseudonymisation"],
        }

        # Calculate HMAC signature over canonical payload bytes
        canonical_bytes = _canonical_json_bytes(payload)
        signature = hmac.new(key_bytes, canonical_bytes, hashlib.sha256).hexdigest()

        audit_document = {
            "audit_payload": payload,
            "integrity_signature": {
                "algorithm": "HMAC-SHA256",
                "signature": signature,
            },
        }
        return audit_document

    @staticmethod
    def verify_audit_log(
        audit_doc_or_path: dict[str, Any] | str | Path,
        signer_key: str,
    ) -> tuple[bool, str]:
        """Verifies the cryptographic integrity of an audit log document.

        Returns:
            (is_valid: bool, message: str)
        """
        if isinstance(audit_doc_or_path, (str, Path)):
            p = Path(audit_doc_or_path)
            if not p.exists():
                return False, f"Audit log file not found: {p}"
            with open(p, encoding="utf-8") as f:
                audit_doc = json.load(f)
        else:
            audit_doc = audit_doc_or_path

        if "audit_payload" not in audit_doc or "integrity_signature" not in audit_doc:
            return False, "Invalid audit log structure: missing payload or signature block."

        payload = audit_doc["audit_payload"]
        sig_block = audit_doc["integrity_signature"]
        expected_sig = sig_block.get("signature")

        if not expected_sig:
            return False, "Audit log signature is empty."

        key_bytes = signer_key.encode("utf-8") if isinstance(signer_key, str) else signer_key
        canonical_bytes = _canonical_json_bytes(payload)
        computed_sig = hmac.new(key_bytes, canonical_bytes, hashlib.sha256).hexdigest()

        if hmac.compare_digest(expected_sig, computed_sig):
            return (
                True,
                f"Audit trail verified! Signed by valid key on {payload.get('timestamp')} for actor '{payload.get('actor')}'.",
            )
        else:
            return (
                False,
                "Cryptographic verification FAILED: Signature mismatch! Audit log has been tampered with or key is incorrect.",
            )


generate_audit_log = AuditTrailManager.generate_audit_log
verify_audit_log = AuditTrailManager.verify_audit_log
