"""Base stream parser interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from typing import IO, TYPE_CHECKING

if TYPE_CHECKING:
    from cloakdb.core.engine import CloakEngine


class BaseStreamParser(ABC):
    """Abstract base class for format-specific streaming parsers."""

    @abstractmethod
    def process_stream(
        self,
        input_stream: IO[str],
        output_stream: IO[str],
        engine: CloakEngine,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> None:
        """Streams records from input_stream, applies masking via engine, and writes to output_stream.

        Args:
            input_stream: Readable text stream.
            output_stream: Writable text stream.
            engine: CloakEngine instance.
            progress_callback: Optional callback `(rows_added, bytes_added)`.
        """
        pass
