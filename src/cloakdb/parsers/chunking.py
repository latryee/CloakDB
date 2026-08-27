"""Multi-core chunk streaming parser for parallel dump anonymization."""

from __future__ import annotations

import io
import json
from collections import deque
from collections.abc import Callable, Iterator
from concurrent.futures import Future, ProcessPoolExecutor
from typing import IO

from cloakdb.config.models import CloakConfig
from cloakdb.core.engine import CloakEngine
from cloakdb.parsers.base import BaseStreamParser
from cloakdb.parsers.sql_dump import _COPY_PATTERN, _INSERT_HEADER_PATTERN, SQLDumpStreamParser


def _process_chunk_worker(
    chunk_text: str,
    config_json: str,
) -> tuple[str, int, int, int]:
    """Worker task executed in worker process.

    Returns:
        (masked_text, rows_processed, cells_masked, bytes_processed)
    """
    config_data = json.loads(config_json)
    config = CloakConfig.model_validate(config_data)
    engine = CloakEngine(config)
    parser = SQLDumpStreamParser()

    in_stream = io.StringIO(chunk_text)
    out_stream = io.StringIO()
    parser.process_stream(in_stream, out_stream, engine)

    return (
        out_stream.getvalue(),
        engine.stats.rows_processed,
        engine.stats.cells_masked,
        engine.stats.bytes_processed,
    )


def _chunk_stream_by_statements(
    input_stream: IO[str],
    target_chunk_lines: int = 2000,
) -> Iterator[str]:
    """Splits an input SQL stream into coherent chunks respecting COPY and multi-line INSERT boundaries."""
    buffer: list[str] = []
    in_copy = False
    in_insert = False

    for line in input_stream:
        buffer.append(line)

        # Track COPY block boundaries
        if in_copy:
            if line.strip() == r"\.":
                in_copy = False
                if len(buffer) >= target_chunk_lines:
                    yield "".join(buffer)
                    buffer = []
            continue

        if _COPY_PATTERN.match(line.strip()):
            in_copy = True
            continue

        # Track multi-line INSERT block boundaries
        if in_insert:
            if ";" in line:
                in_insert = False
                if len(buffer) >= target_chunk_lines:
                    yield "".join(buffer)
                    buffer = []
            continue

        if _INSERT_HEADER_PATTERN.match(line):
            if ";" not in line:
                in_insert = True
            elif len(buffer) >= target_chunk_lines:
                yield "".join(buffer)
                buffer = []
            continue

        if len(buffer) >= target_chunk_lines and not in_copy and not in_insert:
            yield "".join(buffer)
            buffer = []

    if buffer:
        yield "".join(buffer)


class ParallelStreamParser(BaseStreamParser):
    """Multi-process chunk-streaming parser using bounded producer-consumer execution."""

    def __init__(self, workers: int = 4, chunk_lines: int = 2000):
        self.workers = max(1, workers)
        self.chunk_lines = chunk_lines

    def process_stream(
        self,
        input_stream: IO[str],
        output_stream: IO[str],
        engine: CloakEngine,
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> None:
        if self.workers <= 1:
            # Single-worker fallback
            parser = SQLDumpStreamParser()
            parser.process_stream(input_stream, output_stream, engine, progress_callback)
            return

        config_json = engine.config.model_dump_json()
        max_in_flight = max(2, self.workers * 2)
        in_flight_queue: deque[Future[tuple[str, int, int, int]]] = deque()
        total_bytes = 0

        with ProcessPoolExecutor(max_workers=self.workers) as executor:
            for chunk_text in _chunk_stream_by_statements(
                input_stream, target_chunk_lines=self.chunk_lines
            ):
                future = executor.submit(_process_chunk_worker, chunk_text, config_json)
                in_flight_queue.append(future)

                # Maintain bounded in-flight queue for constant RAM usage
                if len(in_flight_queue) >= max_in_flight:
                    completed_future = in_flight_queue.popleft()
                    out_text, rows, cells, bytes_proc = completed_future.result()
                    output_stream.write(out_text)
                    engine.stats.rows_processed += rows
                    engine.stats.cells_masked += cells
                    engine.stats.bytes_processed += bytes_proc
                    total_bytes += bytes_proc
                    if progress_callback:
                        progress_callback(rows, total_bytes)

            # Drain remaining queue in order
            while in_flight_queue:
                completed_future = in_flight_queue.popleft()
                out_text, rows, cells, bytes_proc = completed_future.result()
                output_stream.write(out_text)
                engine.stats.rows_processed += rows
                engine.stats.cells_masked += cells
                engine.stats.bytes_processed += bytes_proc
                total_bytes += bytes_proc
                if progress_callback:
                    progress_callback(rows, total_bytes)
