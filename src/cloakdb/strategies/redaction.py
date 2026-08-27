"""Redaction and pattern-based masking strategies."""

from __future__ import annotations

import re
from typing import Any

from cloakdb.core.context import TransformationContext
from cloakdb.strategies.base import MaskingStrategy
from cloakdb.strategies.registry import register_strategy


@register_strategy("pattern_mask", aliases=["mask", "redact"])
class PatternMaskStrategy(MaskingStrategy):
    """Partially masks strings by preserving head and tail characters while masking the middle."""

    description = "Partially redacts strings (e.g. keeps prefix/suffix, masks middle with '*')"

    def transform(
        self,
        value: Any,
        context: TransformationContext,
        *,
        mask_char: str = "*",
        keep_first: int = 0,
        keep_last: int = 0,
        mask_length: int = 0,
        **kwargs: Any,
    ) -> Any:
        if value is None:
            return None

        val_str = str(value)
        n = len(val_str)

        if n <= (keep_first + keep_last):
            return mask_char * n

        head = val_str[:keep_first] if keep_first > 0 else ""
        tail = val_str[n - keep_last :] if keep_last > 0 else ""
        middle_len = mask_length if mask_length > 0 else (n - keep_first - keep_last)
        middle = mask_char * middle_len

        return f"{head}{middle}{tail}"


@register_strategy("email_mask")
class EmailMaskStrategy(MaskingStrategy):
    """Masks email addresses while optionally keeping initial letters and domain."""

    description = "Redacts email local-part (e.g. 'john.doe@acme.com' -> 'j******e@acme.com')"

    def transform(
        self,
        value: Any,
        context: TransformationContext,
        *,
        mask_char: str = "*",
        keep_first: int = 1,
        keep_last: int = 1,
        preserve_domain: bool = True,
        **kwargs: Any,
    ) -> Any:
        if value is None:
            return None

        val_str = str(value).strip()
        if "@" not in val_str:
            return mask_char * len(val_str)

        local_part, domain = val_str.rsplit("@", 1)
        n = len(local_part)

        if n <= (keep_first + keep_last):
            masked_local = mask_char * n
        else:
            head = local_part[:keep_first]
            tail = local_part[n - keep_last :] if keep_last > 0 else ""
            middle = mask_char * (n - keep_first - keep_last)
            masked_local = f"{head}{middle}{tail}"

        if preserve_domain:
            return f"{masked_local}@{domain}"
        return f"{masked_local}@example.com"


@register_strategy("credit_card_mask")
class CreditCardMaskStrategy(MaskingStrategy):
    """Masks credit card numbers retaining the last 4 digits in standard groups."""

    description = "Formats credit card as '****-****-****-1234'"

    def transform(
        self,
        value: Any,
        context: TransformationContext,
        *,
        mask_char: str = "*",
        **kwargs: Any,
    ) -> Any:
        if value is None:
            return None

        digits = re.sub(r"\D", "", str(value))
        if len(digits) < 4:
            return mask_char * len(str(value))

        last_four = digits[-4:]
        return f"{mask_char * 4}-{mask_char * 4}-{mask_char * 4}-{last_four}"


@register_strategy("regex_replace", aliases=["regex"])
class RegexReplaceStrategy(MaskingStrategy):
    """Substitutes regex pattern matches with replacement string."""

    description = "Regex pattern substitution"

    def transform(
        self,
        value: Any,
        context: TransformationContext,
        *,
        pattern: str = r".",
        replacement: str = "*",
        **kwargs: Any,
    ) -> Any:
        if value is None:
            return None

        return re.sub(pattern, replacement, str(value))
