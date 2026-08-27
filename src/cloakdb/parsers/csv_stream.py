"""High-speed streaming CSV and TSV parser."""

from __future__ import annotations

import csv
from typing import Callable, IO, Optional
from cloakdb.core.engine import CloakEngine
from cloakdb.parsers.base import BaseStreamParser


class CSVStreamParser(BaseStreamParser):
    """Streaming CSV and TSV parser and writer."""

    def __init__(self, table_name: str = "default", delimiter: str = ","):
        self.table_name = table_name
        self.delimiter = delimiter

    def process_stream(
        self,
        input_stream: IO[str],
        output_stream: IO[str],
        engine: CloakEngine,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        reader = csv.reader(input_stream, delimiter=self.delimiter)
        writer = csv.writer(output_stream, delimiter=self.delimiter, lineterminator="\n")

        header = next(reader, None)
        if header is None:
            return

        writer.writerow(header)
        row_count = 0
        bytes_count = 0

        for row in reader:
            masked_row = engine.mask_row_values(
                table_name=self.table_name,
                column_names=header,
                row_values=row,
                row_index=row_count,
            )
            writer.writerow(masked_row)
            row_count += 1

            if progress_callback and row_count % 1000 == 0:
                progress_callback(1000, bytes_count)

        if progress_callback:
            progress_callback(0, bytes_count)
