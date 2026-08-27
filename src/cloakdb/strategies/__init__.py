"""Strategy package initialization and registration triggers."""

from cloakdb.strategies.base import MaskingStrategy
from cloakdb.strategies.registry import StrategyRegistry, register_strategy
import cloakdb.strategies.hash  # noqa: F401
import cloakdb.strategies.synthetic  # noqa: F401
import cloakdb.strategies.redaction  # noqa: F401
import cloakdb.strategies.numeric  # noqa: F401
import cloakdb.strategies.datetime  # noqa: F401
import cloakdb.strategies.general  # noqa: F401

__all__ = [
    "MaskingStrategy",
    "StrategyRegistry",
    "register_strategy",
]
