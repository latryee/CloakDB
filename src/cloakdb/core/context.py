"""Transformation context and runtime statistics for masking operations."""

from __future__ import annotations

from dataclasses import dataclass, field
import time
from typing import Any, Dict, Optional


@dataclass
class MaskingStats:
    """Runtime metrics collected during execution."""

    tables_processed: int = 0
    rows_processed: int = 0
    cells_masked: int = 0
    bytes_processed: int = 0
    start_time: float = field(default_factory=time.perf_counter)
    end_time: Optional[float] = None

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
    row_data: Dict[str, Any] = field(default_factory=dict)
    seed: Optional[int] = 42
    salt: str = "cloakdb-salt"
    locale: str = "en_US"
    stats: MaskingStats = field(default_factory=MaskingStats)
    custom_state: Dict[str, Any] = field(default_factory=dict)

    def derive_seed(self, value: Any = None) -> int:
        """Derives a deterministic 64-bit integer seed combining table, column, salt, and value."""
        import hashlib
        h = hashlib.sha256()
        h.update(self.salt.encode("utf-8"))
        h.update(self.table_name.encode("utf-8"))
        h.update(self.column_name.encode("utf-8"))
        if value is not None:
            h.update(str(value).encode("utf-8"))
        return int.from_bytes(h.digest()[:8], "big")
