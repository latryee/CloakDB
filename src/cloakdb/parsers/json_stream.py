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

        for line_num, line in enumerate(input_stream, start=1):
            line_len = len(line.encode("utf-8"))
            bytes_count += line_len
            engine.stats.bytes_processed += line_len

            line_str = line.strip()
            if not line_str:
                continue

            try:
                record = json.loads(line_str)
            except Exception as exc:
                snippet = line_str[:80] + "..." if len(line_str) > 80 else line_str
                raise ValueError(
                    f"Malformed JSON on line {line_num}: {exc}. Snippet: {snippet!r}"
                ) from exc

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


class JSONDocumentStreamParser(BaseStreamParser):
    """Streaming JSON Document / Array parser for MongoDB exports and JSON array files."""

    def __init__(self, table_name: str = "default"):
        self.table_name = table_name

    def process_stream(
        self,
        input_stream: IO[str],
        output_stream: IO[str],
        engine: CloakEngine,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> None:
        content = input_stream.read()
        engine.stats.bytes_processed += len(content.encode("utf-8"))
        content_stripped = content.strip()

        if not content_stripped:
            return

        try:
            parsed = json.loads(content_stripped)
        except Exception as exc:
            raise ValueError(f"Invalid JSON document payload: {exc}") from exc

        if isinstance(parsed, list):
            output_stream.write("[\n")
            for idx, item in enumerate(parsed):
                if isinstance(item, dict):
                    masked_item = engine.mask_record(
                        table_name=self.table_name,
                        record=item,
                        row_index=idx,
                    )
                else:
                    masked_item = item
                output_stream.write("  " + json.dumps(masked_item, ensure_ascii=False))
                if idx < len(parsed) - 1:
                    output_stream.write(",\n")
                else:
                    output_stream.write("\n")
                if progress_callback and (idx + 1) % 1000 == 0:
                    progress_callback(1000, 0)
            output_stream.write("]\n")
        elif isinstance(parsed, dict):
            masked_doc = engine.mask_record(
                table_name=self.table_name,
                record=parsed,
                row_index=0,
            )
            output_stream.write(json.dumps(masked_doc, indent=2, ensure_ascii=False) + "\n")
            if progress_callback:
                progress_callback(1, 0)
        else:
            output_stream.write(json.dumps(parsed, ensure_ascii=False) + "\n")


