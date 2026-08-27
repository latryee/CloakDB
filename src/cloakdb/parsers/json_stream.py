"""Streaming JSON Lines (.jsonl) parser."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import IO

from cloakdb.core.engine import CloakEngine
from cloakdb.parsers.base import BaseStreamParser


class JSONLinesStreamParser(BaseStreamParser):
    """Streaming JSON Lines (.jsonl) parser and writer."""

    def __init__(self, table_name: str = "default"):
        self.table_name = table_name

    def process_stream(
        self,
        input_stream: IO[str],
        output_stream: IO[str],
        engine: CloakEngine,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> None:
        row_count = 0
        bytes_count = 0

        for line in input_stream:
            line_str = line.strip()
            if not line_str:
                continue

            record = json.loads(line_str)
            masked_record = engine.mask_record(
                table_name=self.table_name,
                record=record,
                row_index=row_count,
            )

            output_stream.write(json.dumps(masked_record, ensure_ascii=False) + "\n")
            row_count += 1

            if progress_callback and row_count % 1000 == 0:
                progress_callback(1000, bytes_count)

        if progress_callback:
            progress_callback(0, bytes_count)
