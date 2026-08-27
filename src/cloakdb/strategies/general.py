"""General, categorical, and algorithmic masking strategies."""

from __future__ import annotations

import random
import string
from typing import Any

from cloakdb.core.context import TransformationContext
from cloakdb.strategies.base import MaskingStrategy
from cloakdb.strategies.registry import register_strategy


@register_strategy("nullify", aliases=["null", "set_null"])
class NullifyStrategy(MaskingStrategy):
    """Sets any value to NULL / None."""

    description = "Replaces value with NULL"

    def transform(
        self,
        value: Any,
        context: TransformationContext,
        **kwargs: Any,
    ) -> Any:
        return None


@register_strategy("constant", aliases=["fixed", "static"])
class ConstantStrategy(MaskingStrategy):
    """Replaces value with a static constant value."""

    description = "Replaces value with a fixed constant (e.g. 'CONFIDENTIAL')"

    def transform(
        self,
        value: Any,
        context: TransformationContext,
        *,
        value_to_set: Any = "REDACTED",
        **kwargs: Any,
    ) -> Any:
        if value is None and kwargs.get("keep_null", True):
            return None
        return value_to_set


@register_strategy("choice", aliases=["random_choice", "pick"])
class ChoiceStrategy(MaskingStrategy):
    """Randomly or deterministically picks an item from a predefined list of choices."""

    description = "Picks a replacement from a categorical list of choices"

    def transform(
        self,
        value: Any,
        context: TransformationContext,
        *,
        choices: list[Any] | None = None,
        deterministic: bool = True,
        **kwargs: Any,
    ) -> Any:
        if value is None:
            return None
        if not choices:
            return value

        rng = random.Random()
        if deterministic:
            rng.seed(context.derive_seed(value))
        return rng.choice(choices)


@register_strategy("scramble", aliases=["shuffle_chars"])
class ScrambleStrategy(MaskingStrategy):
    """Scrambles characters while preserving case, punctuation, and digit structure."""

    description = "Scrambles characters preserving casing and character classes"

    def transform(
        self,
        value: Any,
        context: TransformationContext,
        *,
        deterministic: bool = True,
        **kwargs: Any,
    ) -> Any:
        if value is None:
            return None

        val_str = str(value)
        rng = random.Random()
        if deterministic:
            rng.seed(context.derive_seed(value))

        out_chars = []
        for char in val_str:
            if char.isupper():
                out_chars.append(rng.choice(string.ascii_uppercase))
            elif char.islower():
                out_chars.append(rng.choice(string.ascii_lowercase))
            elif char.isdigit():
                out_chars.append(rng.choice(string.digits))
            else:
                out_chars.append(char)

        return "".join(out_chars)


@register_strategy("tckn", aliases=["turkish_id"])
class TCKNStrategy(MaskingStrategy):
    """Generates an authentic 11-digit Turkish Citizenship Number (TCKN) passing checksum algorithms."""

    description = "Generates a valid checksum 11-digit Turkish Republic ID Number (TCKN)"

    def transform(
        self,
        value: Any,
        context: TransformationContext,
        *,
        deterministic: bool = True,
        **kwargs: Any,
    ) -> Any:
        if value is None:
            return None

        rng = random.Random()
        if deterministic:
            rng.seed(context.derive_seed(value))

        # First digit cannot be 0
        d = [rng.randint(1, 9)]
        for _ in range(8):
            d.append(rng.randint(0, 9))

        # 10th digit = ((d1+d3+d5+d7+d9)*7 - (d2+d4+d6+d8)) % 10
        odd_sum = d[0] + d[2] + d[4] + d[6] + d[8]
        even_sum = d[1] + d[3] + d[5] + d[7]
        d10 = ((odd_sum * 7) - even_sum) % 10
        d.append(d10)

        # 11th digit = sum(d1..d10) % 10
        d11 = sum(d) % 10
        d.append(d11)

        tckn_str = "".join(str(x) for x in d)
        return tckn_str
