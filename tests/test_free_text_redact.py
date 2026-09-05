"""Tests for free-text unstructured PII redaction strategy."""

from __future__ import annotations

from cloakdb.core.context import TransformationContext
from cloakdb.strategies.registry import StrategyRegistry


def test_free_text_redact_strategy_registered():
    """Verify text_redact strategy is registered with registry and aliases."""
    strategy = StrategyRegistry.get("text_redact")
    assert strategy is not None

    alias_strategy = StrategyRegistry.get("free_text_redact")
    assert alias_strategy is not None


def test_free_text_redact_mixed_entities():
    """Test redaction of various PII entities embedded in customer notes."""
    strategy = StrategyRegistry.get("text_redact")

    raw_text = (
        "Customer John Doe called regarding order 123. Contact email: john.doe@example.com. "
        "Verified phone: +1 (555) 234-5678 and SSN: 123-45-6789. "
        "Server reported connection from IP 192.168.1.100."
    )

    context = TransformationContext(
        table_name="support_tickets",
        column_name="notes",
        row_index=0,
        salt="test_salt_123456789012345678901234567890",
    )

    redacted = strategy.transform(raw_text, context, placeholder_style="token")

    assert "john.doe@example.com" not in redacted
    assert "[REDACTED_EMAIL]" in redacted
    assert "123-45-6789" not in redacted
    assert "[REDACTED_SSN]" in redacted
    assert "192.168.1.100" not in redacted
    assert "[REDACTED_IP]" in redacted
    assert "[REDACTED_PHONE]" in redacted
    assert "Customer John Doe called regarding order 123." in redacted


def test_free_text_redact_mask_style():
    """Test masking with asterisks instead of tokens."""
    strategy = StrategyRegistry.get("text_redact")

    raw_text = "Reach me at contact@test.org"
    context = TransformationContext(
        table_name="tickets",
        column_name="body",
        row_index=0,
        salt="test_salt_123456789012345678901234567890",
    )

    redacted = strategy.transform(raw_text, context, placeholder_style="mask", mask_char="*")
    assert "contact@test.org" not in redacted
    assert "Reach me at ****************" in redacted


def test_free_text_redact_selective_entities():
    """Test redacting only specified entity types."""
    strategy = StrategyRegistry.get("text_redact")

    raw_text = "Email: test@example.com, IP: 10.0.0.1"
    context = TransformationContext(
        table_name="tickets",
        column_name="body",
        row_index=0,
        salt="test_salt_123456789012345678901234567890",
    )

    # Only redact email, leave IP intact
    redacted = strategy.transform(raw_text, context, entities=["email"])
    assert "[REDACTED_EMAIL]" in redacted
    assert "10.0.0.1" in redacted
