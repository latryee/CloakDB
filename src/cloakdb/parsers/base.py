"""Base stream parser interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable, IO, Optional
from cloakdb.core.engine import CloakEngine


class BaseStreamParser(ABC):
    """Abstract base class for format-specific streaming parsers."""

    @abstractmethod
    def process_stream(
        self,
        input_stream: IO[str],
        output_stream: IO[str],
        engine: CloakEngine,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        """Streams records from input_stream, applies masking via engine, and writes to output_stream.

        Args:
            input_stream: Readable text stream.
            output_stream: Writable text stream.
            engine: CloakEngine instance.
            progress_callback: Optional callback `(rows_added, bytes_added)`.
        """
        pass
