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

    description = (
        "Deterministic keyed HMAC hash or pseudo-integer (preserves foreign keys across tables)"
    )

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

        effective_salt = salt or context.salt
        group_key = context.group_name or f"{context.table_name}.{context.column_name}"

        # Resolve integrity manager for collision detection & caching
        integrity_mgr = getattr(context, "integrity_manager", None)
        if integrity_mgr is None:
            if "_integrity_mgr" not in context.custom_state:
                from cloakdb.core.integrity import ReferentialIntegrityManager

                context.custom_state["_integrity_mgr"] = ReferentialIntegrityManager()
            integrity_mgr = context.custom_state["_integrity_mgr"]

        # Check existing cached mapping first
        if integrity_mgr is not None:
            cached = integrity_mgr.get_cached_value(group_key, value)
            if cached is not None:
                return cached

        if as_integer or isinstance(value, int):
            span = max_int - min_int + 1
            if span <= 0:
                raise ValueError(f"Invalid integer range: min_int={min_int} > max_int={max_int}")

            counter = 0
            while True:
                if counter == 0:
                    hmac_input = str(value).encode("utf-8")
                else:
                    hmac_input = f"{value}:{counter}".encode()

                h = hmac.new(effective_salt.encode("utf-8"), hmac_input, hashlib.sha256).digest()
                num = int.from_bytes(h[:8], "big")
                res_int = min_int + (num % span)

                if integrity_mgr is not None:
                    if integrity_mgr.is_collision(group_key, value, res_int):
                        counter += 1
                        if counter > span:
                            raise ValueError(
                                f"Integer space exhausted in range [{min_int}, {max_int}] for group '{group_key}'"
                            )
                        continue
                    integrity_mgr.store_cached_value(group_key, value, res_int)
                return res_int

        val_str = str(value).encode("utf-8")
        h = hmac.new(effective_salt.encode("utf-8"), val_str, hashlib.sha256).digest()

        if output_format == "hex":
            digest_str = h.hex()[:length]
        elif output_format == "base64":
            import base64

            digest_str = base64.b64encode(h).decode("ascii")[:length]
        else:
            digest_str = h.hex()[:length]

        masked_val = f"{prefix}{digest_str}{suffix}"
        if integrity_mgr is not None:
            integrity_mgr.store_cached_value(group_key, value, masked_val)
        return masked_val


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

        effective_salt = salt or context.salt
        val_str = f"{effective_salt}:{value}"
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, val_str))
