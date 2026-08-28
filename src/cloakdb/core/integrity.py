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
        # Map table -> list of (tuple_of_cols, group_name) for composite keys
        self._composite_groups_by_table: dict[str, list[tuple[tuple[str, ...], str]]] = {}
        # Map group_name -> ConsistencyGroup
        self._group_definitions: dict[str, ConsistencyGroup] = {}
        # Map group_name -> LRUCache
        self._group_caches: dict[str, LRUCache] = {}
        # Map group_name -> reverse lookup dict (masked_value -> raw_value)
        self._reverse_lookups: dict[str, dict[Any, Any]] = {}

        self._initialize_groups()

    def _initialize_groups(self) -> None:
        for group in self.groups:
            self._group_definitions[group.name] = group
            self._group_caches[group.name] = LRUCache(self.max_cache_size)
            self._reverse_lookups[group.name] = {}
            for col_ref in group.columns:
                ref_clean = col_ref.strip()
                if ".(" in ref_clean and ref_clean.endswith(")"):
                    # Composite key format: table.(col1, col2)
                    tbl_part, cols_part = ref_clean.split(".(", 1)
                    tbl_name = self._normalize_name(tbl_part)
                    cols_list = tuple(
                        self._normalize_name(c) for c in cols_part[:-1].split(",") if c.strip()
                    )
                    self._composite_groups_by_table.setdefault(tbl_name, []).append(
                        (cols_list, group.name)
                    )
                    self._column_to_group[f"{tbl_name}.({','.join(cols_list)})"] = group.name
                else:
                    normalized = self._normalize_column_ref(ref_clean)
                    self._column_to_group[normalized] = group.name

    def _normalize_name(self, name: str) -> str:
        return name.strip().strip('"').strip("`").strip("[]").lower()

    def _normalize_column_ref(self, col_ref: str) -> str:
        parts = [self._normalize_name(p) for p in col_ref.split(".")]
        return ".".join(parts)

    def get_group_for_column(self, table_name: str, column_name: str) -> ConsistencyGroup | None:
        """Returns the ConsistencyGroup for a given table and column if registered."""
        ref = self._normalize_column_ref(f"{table_name}.{column_name}")
        group_name = self._column_to_group.get(ref)
        if group_name:
            return self._group_definitions.get(group_name)
        return None

    def get_composite_groups_for_table(
        self, table_name: str
    ) -> list[tuple[tuple[str, ...], ConsistencyGroup]]:
        """Returns all composite column tuples and their ConsistencyGroup definitions for a table."""
        tbl_norm = self._normalize_name(table_name)
        composite_entries = self._composite_groups_by_table.get(tbl_norm, [])
        results: list[tuple[tuple[str, ...], ConsistencyGroup]] = []
        for cols_tuple, group_name in composite_entries:
            group_def = self._group_definitions.get(group_name)
            if group_def:
                results.append((cols_tuple, group_def))
        return results

    def get_cached_value(self, group_name: str, raw_value: Any) -> Any | None:
        """Retrieves a previously computed pseudonym for a group and raw value."""
        if not self.cache_enabled:
            return None
        cache = self._group_caches.get(group_name)
        if cache:
            val = cache.get(raw_value)
            if val is not None:
                return val
            if isinstance(raw_value, (int, float)):
                val = cache.get(str(raw_value))
                if val is not None:
                    return val
            elif isinstance(raw_value, str):
                try:
                    if raw_value.isdigit() or (
                        raw_value.startswith("-") and raw_value[1:].isdigit()
                    ):
                        val = cache.get(int(raw_value))
                        if val is not None:
                            return val
                except Exception:
                    pass
        return None

    def store_cached_value(self, group_name: str, raw_value: Any, masked_value: Any) -> None:
        """Stores a computed pseudonym in the group cache and reverse lookup mapping."""
        if not self.cache_enabled:
            return
        if group_name not in self._group_caches:
            self._group_caches[group_name] = LRUCache(self.max_cache_size)
        if group_name not in self._reverse_lookups:
            self._reverse_lookups[group_name] = {}
        self._group_caches[group_name].set(raw_value, masked_value)
        self._reverse_lookups[group_name][masked_value] = raw_value

    def is_collision(self, group_name: str, raw_value: Any, masked_value: Any) -> bool:
        """Checks if masked_value is already claimed by a different raw_value in this group."""
        if not self.cache_enabled:
            return False
        rev = self._reverse_lookups.get(group_name)
        if rev is None:
            return False
        existing_raw = rev.get(masked_value)
        if existing_raw is None:
            return False
        if existing_raw == raw_value or str(existing_raw) == str(raw_value):
            return False
        return True

    def get_raw_for_masked(self, group_name: str, masked_value: Any) -> Any | None:
        """Retrieves the raw value associated with a masked value in a group."""
        rev = self._reverse_lookups.get(group_name)
        if rev is not None:
            return rev.get(masked_value)
        return None

    def get_reverse_lookup(self, group_name: str) -> dict[Any, Any]:
        """Returns the reverse lookup mapping (masked_value -> raw_value) for a group."""
        if group_name not in self._reverse_lookups:
            self._reverse_lookups[group_name] = {}
        return self._reverse_lookups[group_name]
