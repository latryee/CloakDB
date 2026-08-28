"""Transformation context and runtime statistics for masking operations."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class MaskingStats:
    """Runtime metrics collected during execution."""

    tables_processed: int = 0
    rows_processed: int = 0
    cells_masked: int = 0
    bytes_processed: int = 0
    start_time: float = field(default_factory=time.perf_counter)
    end_time: float | None = None

    @property
    def elapsed_seconds(self) -> float:
        end = self.end_time or time.perf_counter()
        return max(0.001, end - self.start_time)

    @property
    def rows_per_second(self) -> float:
        return self.rows_processed / self.elapsed_seconds

    @property
    def mb_per_second(self) -> float:
        return (self.bytes_processed / (1024 * 1024)) / self.elapsed_seconds


@dataclass
class TransformationContext:
    """Contextual metadata supplied to each masking strategy during transformation."""

    table_name: str
    column_name: str
    row_index: int
    salt: str
    row_data: dict[str, Any] = field(default_factory=dict)
    seed: int | None = 42
    locale: str = "en_US"
    group_name: str | None = None
    stats: MaskingStats = field(default_factory=MaskingStats)
    custom_state: dict[str, Any] = field(default_factory=dict)
    integrity_manager: Any | None = None

    def derive_seed(self, value: Any = None, scope: str | None = None) -> int:
        """Derives a deterministic 64-bit integer seed.

        Scopes:
            - 'global': based on salt + value
            - 'group': based on salt + group_name + value (used for ConsistencyGroups)
            - 'column': based on salt + table_name + column_name + value (default for un-grouped fields)

        If scope is not explicitly provided, it defaults to 'group' when group_name is set,
        and 'column' otherwise.
        """
        import hashlib

        effective_scope = (
            scope.lower().strip() if scope else ("group" if self.group_name else "column")
        )

        h = hashlib.sha256()
        h.update(self.salt.encode("utf-8"))

        if effective_scope == "global":
            pass
        elif effective_scope == "group":
            grp = self.group_name or "default_group"
            h.update(f"group:{grp}".encode())
        else:  # "column"
            h.update(self.table_name.encode("utf-8"))
            h.update(self.column_name.encode("utf-8"))

        if value is not None:
            h.update(str(value).encode("utf-8"))

        return int.from_bytes(h.digest()[:8], "big")
