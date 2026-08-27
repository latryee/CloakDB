"""Cryptographic and deterministic hashing strategies."""

from __future__ import annotations

import hashlib
import hmac
from typing import Any
from cloakdb.core.context import TransformationContext
from cloakdb.strategies.base import MaskingStrategy
from cloakdb.strategies.registry import register_strategy


@register_strategy("deterministic_hash", aliases=["hash", "hmac", "pseudonymize"])
class DeterministicHashStrategy(MaskingStrategy):
    """Generates a deterministic keyed HMAC-SHA256 hash or mapped integer from input value."""

    description = "Deterministic keyed HMAC hash or pseudo-integer (preserves foreign keys across tables)"

    def transform(
        self,
        value: Any,
        context: TransformationContext,
        *,
        output_format: str = "hex",
        length: int = 16,
        as_integer: bool = False,
        min_int: int = 100000,
        max_int: int = 999999999,
        salt: str = "",
        prefix: str = "",
        suffix: str = "",
        **kwargs: Any,
    ) -> Any:
        if value is None:
            return None

        effective_salt = salt or context.salt or "cloakdb-salt"
        val_str = str(value).encode("utf-8")
        h = hmac.new(effective_salt.encode("utf-8"), val_str, hashlib.sha256).digest()

        if as_integer or isinstance(value, int):
            num = int.from_bytes(h[:8], "big")
            span = max_int - min_int + 1
            res_int = min_int + (num % span)
            return res_int

        if output_format == "hex":
            digest_str = h.hex()[:length]
        elif output_format == "base64":
            import base64
            digest_str = base64.b64encode(h).decode("ascii")[:length]
        else:
            digest_str = h.hex()[:length]

        return f"{prefix}{digest_str}{suffix}"


@register_strategy("uuid_hash", aliases=["uuid"])
class DeterministicUUIDStrategy(MaskingStrategy):
    """Generates a deterministic UUID (version 4 or version 5 style) based on input value and salt."""

    description = "Generates a RFC 4122 compliant deterministic UUID derived from input"

    def transform(
        self,
        value: Any,
        context: TransformationContext,
        *,
        salt: str = "",
        **kwargs: Any,
    ) -> Any:
        if value is None:
            return None

        import uuid
        effective_salt = salt or context.salt or "cloakdb-salt"
        val_str = f"{effective_salt}:{value}"
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, val_str))
