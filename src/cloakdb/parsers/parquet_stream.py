"""Streaming parser and writer for Apache Parquet datasets."""

from __future__ import annotations

import io
from collections.abc import Callable
from pathlib import Path
from typing import IO, TYPE_CHECKING, Any

from cloakdb.parsers.base import BaseStreamParser

if TYPE_CHECKING:
    from cloakdb.core.engine import CloakEngine


class ParquetStreamParser(BaseStreamParser):
    """Streams and masks Apache Parquet files in row-group / batch chunks with bounded memory."""

    def __init__(self, table_name: str = "default", batch_size: int = 5000) -> None:
        super().__init__()
        self.table_name = table_name
        self.batch_size = batch_size

    def process_stream(
        self,
        input_stream: IO[str],
        output_stream: IO[str],
        engine: CloakEngine,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> None:
        """Processes a Parquet stream from binary or text file buffer."""
        try:
            import pyarrow as pa
            import pyarrow.parquet as pq
        except ImportError as err:
            raise ImportError(
                "Apache Parquet support requires 'pyarrow'. Install with: pip install 'cloakdb[parquet]'"
            ) from err

        raw = input_stream.read()
        raw_bytes = raw.encode("latin1") if isinstance(raw, str) else raw
        buf = io.BytesIO(raw_bytes)

        pq_file = pq.ParquetFile(buf)
        schema = pq_file.schema_arrow

        out_buf = io.BytesIO()
        writer: Any = None
        rows_total = 0

        for batch in pq_file.iter_batches(batch_size=self.batch_size):
            pydict = batch.to_pydict()
            col_names = list(pydict.keys())
            num_rows = len(batch)
            if num_rows == 0:
                continue

            masked_dict: dict[str, list[Any]] = {col: [] for col in col_names}

            for row_idx in range(num_rows):
                record = {col: pydict[col][row_idx] for col in col_names}
                masked_record = engine.mask_record(self.table_name, record)
                for col in col_names:
                    masked_dict[col].append(masked_record.get(col, record[col]))
                rows_total += 1

            masked_batch = pa.RecordBatch.from_pydict(masked_dict, schema=schema)
            if writer is None:
                writer = pq.ParquetWriter(out_buf, schema)
            writer.write_batch(masked_batch)

            if progress_callback:
                progress_callback(rows_total, len(raw_bytes))

        if writer is not None:
            writer.close()

        out_bytes = out_buf.getvalue()
        output_stream.write(out_bytes.decode("latin1"))

    def process_file_chunked(
        self,
        input_path: Path | str,
        output_path: Path | str,
        engine: CloakEngine,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> int:
        """Processes a Parquet file on disk using true disk-to-disk streaming without buffer overhead."""
        try:
            import pyarrow as pa
            import pyarrow.parquet as pq
        except ImportError as err:
            raise ImportError(
                "Apache Parquet support requires 'pyarrow'. Install with: pip install 'cloakdb[parquet]'"
            ) from err

        in_p = Path(input_path)
        out_p = Path(output_path)
        file_size = in_p.stat().st_size

        pq_file = pq.ParquetFile(str(in_p))
        schema = pq_file.schema_arrow
        rows_total = 0

        with pq.ParquetWriter(str(out_p), schema) as writer:
            for batch in pq_file.iter_batches(batch_size=self.batch_size):
                pydict = batch.to_pydict()
                col_names = list(pydict.keys())
                num_rows = len(batch)
                if num_rows == 0:
                    continue

                masked_dict: dict[str, list[Any]] = {col: [] for col in col_names}

                for row_idx in range(num_rows):
                    record = {col: pydict[col][row_idx] for col in col_names}
                    masked_record = engine.mask_record(self.table_name, record)
                    for col in col_names:
                        masked_dict[col].append(masked_record.get(col, record[col]))
                    rows_total += 1

                masked_batch = pa.RecordBatch.from_pydict(masked_dict, schema=schema)
                writer.write_batch(masked_batch)

                if progress_callback:
                    progress_callback(rows_total, file_size)

        return rows_total
