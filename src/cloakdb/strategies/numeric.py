"""Numeric transformation and statistical noise masking strategies."""

from __future__ import annotations

import random
from typing import Any, Optional, Union
from cloakdb.core.context import TransformationContext
from cloakdb.strategies.base import MaskingStrategy
from cloakdb.strategies.registry import register_strategy


@register_strategy("jitter", aliases=["numeric_noise", "noise"])
class NumericJitterStrategy(MaskingStrategy):
    """Adds statistical noise (Gaussian or Uniform percentage) to numeric columns."""

    description = "Adds percentage noise to numeric values while preserving statistical distribution"

    def transform(
        self,
        value: Any,
        context: TransformationContext,
        *,
        percentage: float = 10.0,
        distribution: str = "uniform",
        decimals: Optional[int] = None,
        min_val: Optional[float] = None,
        max_val: Optional[float] = None,
        deterministic: bool = True,
        **kwargs: Any,
    ) -> Any:
        if value is None:
            return None

        try:
            val_num = float(value)
        except (ValueError, TypeError):
            return value

        rng = random.Random()
        if deterministic:
            rng.seed(context.derive_seed(value))

        fraction = percentage / 100.0
        if distribution == "gaussian":
            # Normal distribution with mean=1.0 and stddev=fraction/2
            factor = rng.gauss(1.0, fraction / 2.0)
        else:
            # Uniform distribution in [1.0 - fraction, 1.0 + fraction]
            factor = rng.uniform(1.0 - fraction, 1.0 + fraction)

        new_val = val_num * factor

        if min_val is not None:
            new_val = max(min_val, new_val)
        if max_val is not None:
            new_val = min(max_val, new_val)

        # Preserve original type if integer
        if isinstance(value, int) and decimals is None:
            return int(round(new_val))

        if decimals is not None:
            return round(new_val, decimals)

        return new_val


@register_strategy("range_random", aliases=["random_int", "random_float"])
class RangeRandomStrategy(MaskingStrategy):
    """Generates random numeric values within specified bounds."""

    description = "Generates random numbers bounded between min and max"

    def transform(
        self,
        value: Any,
        context: TransformationContext,
        *,
        min_val: Union[int, float] = 0,
        max_val: Union[int, float] = 100,
        as_integer: bool = True,
        deterministic: bool = True,
        **kwargs: Any,
    ) -> Any:
        if value is None:
            return None

        rng = random.Random()
        if deterministic:
            rng.seed(context.derive_seed(value))

        if as_integer:
            return rng.randint(int(min_val), int(max_val))
        return rng.uniform(float(min_val), float(max_val))


@register_strategy("round_to", aliases=["round", "bucket"])
class RoundToStrategy(MaskingStrategy):
    """Buckets numeric values to the nearest multiple or step."""

    description = "Rounds numbers to nearest step (e.g. nearest 1000 for k-anonymity)"

    def transform(
        self,
        value: Any,
        context: TransformationContext,
        *,
        step: Union[int, float] = 10,
        **kwargs: Any,
    ) -> Any:
        if value is None:
            return None

        try:
            val_num = float(value)
            res = round(val_num / step) * step
            if isinstance(value, int):
                return int(res)
            return res
        except (ValueError, TypeError):
            return value
