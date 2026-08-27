"""Base database connector interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional
from cloakdb.core.engine import CloakEngine


class BaseDatabaseConnector(ABC):
    """Abstract base connector for live database systems."""

    @abstractmethod
    def get_table_names(self) -> List[str]:
        """Returns all user table names in the database."""
        pass

    @abstractmethod
    def get_table_columns(self, table_name: str) -> List[Dict[str, Any]]:
        """Returns column names and types for a table."""
        pass

    @abstractmethod
    def mask_table(
        self,
        table_name: str,
        engine: CloakEngine,
        batch_size: int = 5000,
        progress_callback: Optional[Callable[[int], None]] = None,
    ) -> int:
        """Masks records in a table, returning total rows affected."""
        pass
