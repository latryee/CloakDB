"""Base abstraction and protocol for masking strategies."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from cloakdb.core.context import TransformationContext


class MaskingStrategy(ABC):
    """Abstract base class for all data masking strategies."""

    name: str = ""
    description: str = ""

    @abstractmethod
    def transform(
        self,
        value: Any,
        context: TransformationContext,
        **params: Any,
    ) -> Any:
        """Transforms a single database cell value according to strategy parameters.

        Args:
            value: The raw input value (can be str, int, float, None, datetime, etc.)
            context: Runtime context including table, column, seed, salt, row index.
            **params: Strategy-specific configuration parameters.

        Returns:
            The anonymized / masked value.
        """
        pass

    def validate_params(self, params: dict[str, Any]) -> None:
        """Validates configuration parameters for the strategy."""
        pass
