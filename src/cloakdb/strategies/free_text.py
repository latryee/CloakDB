"""Free-text unstructured PII redaction strategy."""

from __future__ import annotations

import re
from typing import Any

from cloakdb.core.context import TransformationContext
from cloakdb.strategies.base import MaskingStrategy
from cloakdb.strategies.registry import register_strategy
from cloakdb.utils.checksums import validate_iban, validate_luhn, validate_tckn

# Regex patterns for unstructured free-text extraction
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
_CREDIT_CARD_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
_TCKN_RE = re.compile(r"\b[1-9]\d{10}\b")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b")
_PHONE_RE = re.compile(r"(?:\+?\d{1,3}[ -.]?)?\(?\d{3}\)?[ -.]?\d{3}[ -.]?\d{4}\b")


@register_strategy("text_redact", aliases=["free_text_redact", "unstructured_redact"])
class FreeTextRedactStrategy(MaskingStrategy):
    """Redacts multiple PII entities in unstructured free-text fields (e.g. customer notes, logs)."""

    description = (
        "In-place redaction of emails, phones, credit cards, TCKN, SSN, and IPs in free-text."
    )

    def transform(
        self,
        value: Any,
        context: TransformationContext,
        *,
        entities: list[str] | None = None,
        placeholder_style: str = "token",
        mask_char: str = "*",
        validate_checksums: bool = True,
        **kwargs: Any,
    ) -> Any:
        if value is None:
            return None

        text = str(value)
        if not text:
            return text

        active_entities = (
            set(entities)
            if entities
            else {
                "email",
                "credit_card",
                "tckn",
                "ssn",
                "iban",
                "ipv4",
                "phone",
            }
        )

        # 1. Email Redaction
        if "email" in active_entities:

            def _replace_email(match: re.Match[str]) -> str:
                matched_str = match.group(0)
                if placeholder_style == "token":
                    return "[REDACTED_EMAIL]"
                return mask_char * len(matched_str)

            text = _EMAIL_RE.sub(_replace_email, text)

        # 2. IBAN Redaction
        if "iban" in active_entities:

            def _replace_iban(match: re.Match[str]) -> str:
                matched_str = match.group(0)
                if validate_checksums and not validate_iban(matched_str):
                    return matched_str
                if placeholder_style == "token":
                    return "[REDACTED_IBAN]"
                return mask_char * len(matched_str)

            text = _IBAN_RE.sub(_replace_iban, text)

        # 3. Credit Card Redaction
        if "credit_card" in active_entities:

            def _replace_card(match: re.Match[str]) -> str:
                matched_str = match.group(0)
                digits_only = re.sub(r"\D", "", matched_str)
                if len(digits_only) < 13 or len(digits_only) > 19:
                    return matched_str
                if validate_checksums and not validate_luhn(matched_str):
                    return matched_str
                if placeholder_style == "token":
                    return "[REDACTED_CARD]"
                return mask_char * len(matched_str)

            text = _CREDIT_CARD_RE.sub(_replace_card, text)

        # 4. Turkish TCKN Redaction
        if "tckn" in active_entities:

            def _replace_tckn(match: re.Match[str]) -> str:
                matched_str = match.group(0)
                if validate_checksums and not validate_tckn(matched_str):
                    return matched_str
                if placeholder_style == "token":
                    return "[REDACTED_TCKN]"
                return mask_char * len(matched_str)

            text = _TCKN_RE.sub(_replace_tckn, text)

        # 5. US SSN Redaction
        if "ssn" in active_entities:

            def _replace_ssn(match: re.Match[str]) -> str:
                matched_str = match.group(0)
                if placeholder_style == "token":
                    return "[REDACTED_SSN]"
                return mask_char * len(matched_str)

            text = _SSN_RE.sub(_replace_ssn, text)

        # 6. IPv4 Redaction
        if "ipv4" in active_entities or "ip" in active_entities:

            def _replace_ip(match: re.Match[str]) -> str:
                matched_str = match.group(0)
                if placeholder_style == "token":
                    return "[REDACTED_IP]"
                return mask_char * len(matched_str)

            text = _IPV4_RE.sub(_replace_ip, text)

        # 7. Phone Number Redaction
        if "phone" in active_entities:

            def _replace_phone(match: re.Match[str]) -> str:
                matched_str = match.group(0)
                if placeholder_style == "token":
                    return "[REDACTED_PHONE]"
                return mask_char * len(matched_str)

            text = _PHONE_RE.sub(_replace_phone, text)

        return text
