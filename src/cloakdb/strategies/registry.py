"""Strategy registry for dynamic strategy discovery, lookup, and documentation."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Type
from cloakdb.strategies.base import MaskingStrategy


class StrategyRegistry:
    """Singleton-like registry containing all available masking strategies."""

    _strategies: Dict[str, MaskingStrategy] = {}
    _aliases: Dict[str, str] = {}

    @classmethod
    def register(
        cls,
        name: str,
        aliases: Optional[List[str]] = None,
    ) -> Callable[[Type[MaskingStrategy]], Type[MaskingStrategy]]:
        """Class decorator to register a strategy implementation."""
        def decorator(strategy_cls: Type[MaskingStrategy]) -> Type[MaskingStrategy]:
            instance = strategy_cls()
            instance.name = name
            key = name.lower().strip()
            cls._strategies[key] = instance
            if aliases:
                for alias in aliases:
                    cls._aliases[alias.lower().strip()] = key
            return strategy_cls

        return decorator

    @classmethod
    def get(cls, name: str) -> MaskingStrategy:
        """Retrieves a registered strategy by name or alias."""
        key = name.lower().strip()
        if key in cls._aliases:
            key = cls._aliases[key]
        if key not in cls._strategies:
            available = ", ".join(sorted(cls._strategies.keys()))
            raise KeyError(
                f"Unknown masking strategy '{name}'. Available strategies: {available}"
            )
        return cls._strategies[key]

    @classmethod
    def list_strategies(cls) -> List[Dict[str, Any]]:
        """Returns metadata for all registered strategies."""
        results = []
        for name, strategy in sorted(cls._strategies.items()):
            aliases = [a for a, target in cls._aliases.items() if target == name]
            results.append({
                "name": name,
                "description": strategy.description or strategy.__doc__ or "No description",
                "aliases": aliases,
                "class": strategy.__class__.__name__,
            })
        return results


register_strategy = StrategyRegistry.register
