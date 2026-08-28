"""Security and credential redaction helper utilities."""

from __future__ import annotations

import re


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
