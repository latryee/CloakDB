"""Security and credential redaction helper utilities."""

from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urlparse

KNOWN_WEAK_SALTS: set[str] = {
    "cloakdb-salt",
    "cloakdb-default-salt-v1",
    "cloakdb-secure-salt",
    "default",
    "secret",
    "password",
    "123456",
    "test",
    "salt",
    "admin",
    "changeme",
    "placeholder",
    "demo",
    "sample",
    "cloakdb",
}


def is_insecure_salt(salt: str | None) -> tuple[bool, str]:
    """Evaluates if a salt string is cryptographically insecure or default.

    Returns:
        (is_insecure: bool, reason: str)
    """
    if salt is None or not isinstance(salt, str):
        return True, "Salt is missing or not a string."

    trimmed = salt.strip()
    if not trimmed:
        return True, "Salt is empty."

    if trimmed.lower() in KNOWN_WEAK_SALTS or any(
        trimmed.lower().startswith(w) for w in ("cloakdb-salt", "default", "test-salt")
    ):
        return (
            True,
            f"Salt '{trimmed}' is a known default/placeholder value vulnerable to precomputation.",
        )

    if len(trimmed) < 32:
        return (
            True,
            f"Salt length ({len(trimmed)} chars) is below the minimum 32-character requirement for brute-force resistance.",
        )

    return False, ""


def compute_salt_fingerprint(salt: str) -> str:
    """Computes a deterministic SHA-256 fingerprint (first 16 hex chars) of a salt."""
    if not salt:
        return ""
    return hashlib.sha256(salt.strip().encode("utf-8")).hexdigest()[:16]


def is_production_connection(url: str) -> bool:
    """Detects if a connection URL appears to target a live production database.

    Inspects hostname, database name, and URL components for keywords such as:
    'prod', 'production', 'live', 'main', 'master', 'rds.amazonaws.com', etc.
    """
    if not isinstance(url, str) or "://" not in url:
        return False

    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower().lstrip("/")

        prod_patterns = [
            r"\bprod\b",
            r"production",
            r"\blive\b",
            r"\bmaster\b",
            r"main[-_]?db",
            r"rds\.amazonaws\.com",
            r"database\.windows\.net",
            r"gcp\.cloudsql",
        ]

        for pattern in prod_patterns:
            if re.search(pattern, host) or re.search(pattern, path):
                return True

        return False
    except Exception:
        return False


def redact_connection_url(url: str) -> str:
    """Masks the password portion of userinfo in database connection URLs.

    Examples:
        - `postgresql://user:secret@localhost:5432/db` -> `postgresql://user:***@localhost:5432/db`
        - `postgresql://user@localhost:5432/db` -> `postgresql://user@localhost:5432/db`
        - `/path/to/dump.sql` -> `/path/to/dump.sql`

    Non-URL strings (such as file paths) are returned unchanged.
    """
    if not isinstance(url, str) or "://" not in url:
        return url

    try:
        scheme, rest = url.split("://", 1)
        # Find where authority ends (at first '/', '?', or '#')
        end_idx = len(rest)
        for char in ("/", "?", "#"):
            idx = rest.find(char)
            if idx != -1 and idx < end_idx:
                end_idx = idx

        authority = rest[:end_idx]
        suffix = rest[end_idx:]

        if "@" in authority:
            userinfo, host_part = authority.rsplit("@", 1)
            if ":" in userinfo:
                username, _ = userinfo.split(":", 1)
                authority = f"{username}:***@{host_part}"
                return f"{scheme}://{authority}{suffix}"

        return url
    except Exception:
        return url


def hkdf_derive_key(salt: str | bytes, info: str | bytes = b"cloakdb-key", length: int = 32) -> bytes:
    """Derives a cryptographically strong subkey using HKDF-SHA256 (RFC 5869)."""
    import hmac

    salt_bytes = salt.encode("utf-8") if isinstance(salt, str) else salt
    info_bytes = info.encode("utf-8") if isinstance(info, str) else info

    # Step 1: Extract PRK = HMAC-Hash(salt, IKM)
    prk = hmac.new(salt_bytes, b"cloakdb-master-key", hashlib.sha256).digest()

    # Step 2: Expand OKM = HMAC-Hash(PRK, info || 0x01)
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info_bytes + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1

    return okm[:length]


def keyed_mac_hash(key: str | bytes, data: str | bytes) -> str:
    """Computes a keyed HMAC-SHA256 digest string."""
    import hmac

    k_bytes = key.encode("utf-8") if isinstance(key, str) else key
    d_bytes = data.encode("utf-8") if isinstance(data, str) else data
    return hmac.new(k_bytes, d_bytes, hashlib.sha256).hexdigest()


def zeroize_memory(target: Any) -> bool:
    """Securely wipes mutable memory buffers (bytearray, ctypes buffers, dicts, lists).

    Overwrites in-place with zero bytes to prevent cryptographic material from
    lingering in process memory post-execution.
    """
    if target is None:
        return True

    try:
        import ctypes

        if isinstance(target, bytearray):
            for idx in range(len(target)):
                target[idx] = 0
            return True

        if isinstance(target, (memoryview, ctypes.Array)):
            ctypes.memset(ctypes.addressof(target), 0, len(target))
            return True

        if hasattr(target, "__dict__"):
            # Clear internal dictionary mappings
            if isinstance(target.__dict__, dict):
                for k in list(target.__dict__.keys()):
                    val = target.__dict__[k]
                    if isinstance(val, bytearray):
                        for idx in range(len(val)):
                            val[idx] = 0
            return True

        if isinstance(target, dict):
            for k in list(target.keys()):
                val = target[k]
                if isinstance(val, bytearray):
                    for idx in range(len(val)):
                        val[idx] = 0
            target.clear()
            return True

        if isinstance(target, list):
            target.clear()
            return True

        return True
    except Exception:
        return False
