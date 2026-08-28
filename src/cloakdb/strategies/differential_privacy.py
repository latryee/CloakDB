"""Differential Privacy masking strategies (Laplace & Gaussian mechanisms)."""

from __future__ import annotations

import math
import random
from typing import Any

from cloakdb.core.context import TransformationContext
from cloakdb.strategies.base import MaskingStrategy
from cloakdb.strategies.registry import register_strategy


@register_strategy(
    "differential_privacy", aliases=["dp", "laplace_noise", "gaussian_noise", "dp_noise"]
)
class DifferentialPrivacyStrategy(MaskingStrategy):
    r"""Adds calibrated differential privacy noise (Laplace or Gaussian) to numeric columns.

    Mathematical guarantees:
    - Laplace Mechanism provides \(\epsilon\)-Differential Privacy by adding noise drawn from
      \(\text{Laplace}(0, \frac{\Delta f}{\epsilon})\).
    - Gaussian Mechanism provides \((\epsilon, \delta)\)-Differential Privacy by adding noise drawn from
      \(\mathcal{N}(0, \sigma^2)\) where \(\sigma = \frac{\sqrt{2\ln(1.25/\delta)}\Delta f}{\epsilon}\).
    """

    description = (
        "Adds mathematically provable (epsilon, delta) Differential Privacy noise to numeric data"
    )

    def transform(
        self,
        value: Any,
        context: TransformationContext,
        *,
        epsilon: float = 1.0,
        sensitivity: float = 1.0,
        mechanism: str = "laplace",
        delta: float = 1e-5,
        min_val: float | None = None,
        max_val: float | None = None,
        decimals: int | None = None,
        as_integer: bool = False,
        deterministic: bool = True,
        **kwargs: Any,
    ) -> Any:
        if value is None:
            return None

        try:
            val_num = float(value)
        except (ValueError, TypeError):
            return value

        if epsilon <= 0:
            raise ValueError(f"Differential privacy parameter epsilon must be > 0, got {epsilon}")

        if sensitivity <= 0:
            raise ValueError(f"Query sensitivity must be > 0, got {sensitivity}")

        # Deterministic or Stochastic PRNG
        if deterministic:
            import hashlib

            token = f"dp:{context.salt}:{context.table_name}:{context.column_name}:{value}:{context.row_index}".encode()
            seed_int = int.from_bytes(hashlib.sha256(token).digest()[:8], "big")
            rng = random.Random(seed_int)
        else:
            rng = random.Random()

        # Compute calibrated noise
        mech_lower = mechanism.lower()
        if mech_lower in ("gaussian", "normal"):
            if delta <= 0 or delta >= 1:
                raise ValueError(f"Gaussian mechanism requires 0 < delta < 1, got {delta}")
            # sigma = sqrt(2 * ln(1.25 / delta)) * sensitivity / epsilon
            sigma = (math.sqrt(2.0 * math.log(1.25 / delta)) * sensitivity) / epsilon
            noise = rng.gauss(0.0, sigma)
        else:
            # Laplace mechanism: b = sensitivity / epsilon
            # Generate Laplace noise via inverse CDF: x = -b * sign(u) * ln(1 - 2|u|) where u in (-0.5, 0.5)
            scale = sensitivity / epsilon
            u = rng.uniform(-0.5, 0.5)
            if u == 0:
                noise = 0.0
            else:
                sign = 1.0 if u > 0 else -1.0
                noise = -scale * sign * math.log(1.0 - 2.0 * abs(u))

        perturbed = val_num + noise

        # Optional bounds clamping
        if min_val is not None:
            perturbed = max(min_val, perturbed)
        if max_val is not None:
            perturbed = min(max_val, perturbed)

        # Type and precision formatting
        if as_integer or (isinstance(value, int) and decimals is None):
            return int(round(perturbed))

        if decimals is not None:
            return round(perturbed, decimals)

        return perturbed
