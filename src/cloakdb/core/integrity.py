"""Referential integrity and cross-table consistency management."""

from __future__ import annotations

from collections import OrderedDict
from typing import Any

from cloakdb.config.models import ConsistencyGroup


class LRUCache:
    """Lightweight bounded LRU Cache to maintain pseudonym mappings without memory explosion."""

    def __init__(self, capacity: int = 500000):
        self.capacity = capacity
        self._cache: OrderedDict[Any, Any] = OrderedDict()

    def get(self, key: Any) -> Any | None:
        if key not in self._cache:
            return None
        self._cache.move_to_end(key)
        return self._cache[key]

    def set(self, key: Any, value: Any) -> None:
        if key in self._cache:
            self._cache.move_to_end(key)
        self._cache[key] = value
        if len(self._cache) > self.capacity:
            self._cache.popitem(last=False)

    def contains(self, key: Any) -> bool:
        return key in self._cache

    def clear(self) -> None:
        self._cache.clear()


class ReferentialIntegrityManager:
    """Manages consistency groups and cross-table referential integrity.

    Ensures foreign keys and shared entities across tables (e.g., users.id <-> orders.user_id)
    receive identical pseudonyms.
    """

    def __init__(
        self,
        groups: list[ConsistencyGroup] | None = None,
        max_cache_size: int = 500000,
        cache_enabled: bool = True,
    ):
        self.groups = groups or []
        self.cache_enabled = cache_enabled
        self.max_cache_size = max_cache_size

        # Map 'table.column' -> group_name
        self._column_to_group: dict[str, str] = {}
        # Map group_name -> ConsistencyGroup
        self._group_definitions: dict[str, ConsistencyGroup] = {}
        # Map group_name -> LRUCache
        self._group_caches: dict[str, LRUCache] = {}

        self._initialize_groups()

    def _initialize_groups(self) -> None:
        for group in self.groups:
            self._group_definitions[group.name] = group
            self._group_caches[group.name] = LRUCache(self.max_cache_size)
            for col_ref in group.columns:
                normalized = self._normalize_column_ref(col_ref)
                self._column_to_group[normalized] = group.name

    def _normalize_column_ref(self, col_ref: str) -> str:
        parts = [p.strip().strip('"').strip("`").strip("[]").lower() for p in col_ref.split(".")]
        return ".".join(parts)

    def get_group_for_column(self, table_name: str, column_name: str) -> ConsistencyGroup | None:
        """Returns the ConsistencyGroup for a given table and column if registered."""
        ref = self._normalize_column_ref(f"{table_name}.{column_name}")
        group_name = self._column_to_group.get(ref)
        if group_name:
            return self._group_definitions.get(group_name)
        return None

    def get_cached_value(self, group_name: str, raw_value: Any) -> Any | None:
        """Retrieves a previously computed pseudonym for a group and raw value."""
        if not self.cache_enabled:
            return None
        cache = self._group_caches.get(group_name)
        if cache:
            return cache.get(raw_value)
        return None

    def store_cached_value(self, group_name: str, raw_value: Any, masked_value: Any) -> None:
        """Stores a computed pseudonym in the group cache."""
        if not self.cache_enabled:
            return
        if group_name not in self._group_caches:
            self._group_caches[group_name] = LRUCache(self.max_cache_size)
        self._group_caches[group_name].set(raw_value, masked_value)
