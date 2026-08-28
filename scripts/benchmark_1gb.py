"""End-to-End Performance and Throughput Benchmark for 1GB+ SQL Dumps.

Generates realistic multi-table relational SQL dump streams and measures
streaming throughput, processing time, rows/sec, MB/s, and memory consumption.
"""

from __future__ import annotations

import argparse
import secrets
import tempfile
import time
import tracemalloc
from pathlib import Path

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cloakdb.config.models import CloakConfig, ColumnRule, ConsistencyGroup, GlobalConfig, TableRule
from cloakdb.core.engine import CloakEngine
from cloakdb.parsers.chunking import ParallelStreamParser
from cloakdb.parsers.sql_dump import SQLDumpStreamParser

console = Console()


def generate_benchmark_sql_dump(
    file_path: Path,
    target_rows: int = 500000,
    progress_fn=None,
) -> int:
    """Generates a synthetic, high-volume multi-table PostgreSQL dump with FKs and PII."""
    first_names = ["James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael", "Linda"]
    last_names = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis"]
    domains = ["gmail.com", "yahoo.com", "corp.example.com", "techhub.io", "outlook.com"]
    cities = ["New York", "London", "Berlin", "Tokyo", "Paris", "Sydney", "Toronto"]

    with file_path.open("w", encoding="utf-8", newline="\n") as f:
        # 1. DDL Header
        f.write("-- CloakDB Enterprise 1GB+ Streaming Benchmark Fixture\n")
        f.write("SET client_encoding = 'UTF8';\n\n")

        # 2. Table: users
        f.write(
            "CREATE TABLE users (id INT PRIMARY KEY, full_name VARCHAR(100), email VARCHAR(150), phone VARCHAR(30), salary NUMERIC(10, 2), ssn VARCHAR(20));\n"
        )
        f.write("COPY users (id, full_name, email, phone, salary, ssn) FROM stdin;\n")

        user_count = max(1000, target_rows // 2)
        for uid in range(1, user_count + 1):
            fn = first_names[uid % len(first_names)]
            ln = last_names[uid % len(last_names)]
            full_name = f"{fn} {ln}"
            email = f"{fn.lower()}.{ln.lower()}{uid}@{domains[uid % len(domains)]}"
            phone = f"+1-555-{100 + (uid % 900):03d}-{1000 + (uid % 9000):04d}"
            salary = f"{45000.0 + (uid % 120000):.2f}"
            ssn = f"{100 + (uid % 800):03d}-{10 + (uid % 80):02d}-{1000 + (uid % 9000):04d}"
            line = f"{uid}\t{full_name}\t{email}\t{phone}\t{salary}\t{ssn}\n"
            f.write(line)

        f.write("\\.\n\n")

        # 3. Table: orders (Relational child referencing users.id)
        f.write(
            "CREATE TABLE orders (order_id INT PRIMARY KEY, user_id INT, amount NUMERIC(10, 2), shipping_address VARCHAR(200), credit_card VARCHAR(30));\n"
        )
        f.write(
            "COPY orders (order_id, user_id, amount, shipping_address, credit_card) FROM stdin;\n"
        )

        order_count = target_rows - user_count
        for oid in range(1, order_count + 1):
            uid = 1 + (oid % user_count)
            amount = f"{10.0 + (oid % 1500):.2f}"
            city = cities[oid % len(cities)]
            addr = f"{100 + (oid % 900)} Market St, {city}"
            cc = f"411111111111{oid % 10000:04d}"
            line = f"{oid}\t{uid}\t{amount}\t{addr}\t{cc}\n"
            f.write(line)

        f.write("\\.\n\n")

    return file_path.stat().st_size


def run_1gb_benchmark(
    target_size_mb: int = 100,
    workers: int = 1,
    chunk_lines: int = 5000,
    keep_temp: bool = False,
) -> dict[str, float]:
    """Executes the full end-to-end benchmark on generated SQL dumps."""
    # Approximate row count: 1 row is ~120 bytes -> ~8,500 rows per MB
    approx_rows = int(target_size_mb * 8500)
    console.print(
        Panel(
            f"[bold cyan]CloakDB High-Scale Benchmark[/bold cyan]\n"
            f"Target Size:    [bold yellow]{target_size_mb} MB[/bold yellow]\n"
            f"Approx Rows:    [bold yellow]{approx_rows:,} rows[/bold yellow]\n"
            f"Workers:        [bold yellow]{workers} process(es)[/bold yellow]\n"
            f"Chunk Lines:    [bold yellow]{chunk_lines:,}[/bold yellow]",
            title="[bold green]Benchmark Parameters[/bold green]",
            border_style="green",
        )
    )

    with tempfile.TemporaryDirectory() as tmp_dir:
        input_dump = Path(tmp_dir) / "large_dump.sql"
        output_dump = Path(tmp_dir) / "masked_dump.sql"

        console.print("[dim]Generating synthetic multi-table SQL dataset...[/dim]")
        gen_start = time.perf_counter()
        actual_bytes = generate_benchmark_sql_dump(input_dump, target_rows=approx_rows)
        actual_mb = actual_bytes / (1024 * 1024)
        gen_duration = time.perf_counter() - gen_start
        console.print(
            f"[bold green][+] Generated {actual_mb:.2f} MB SQL dump in {gen_duration:.2f}s[/bold green]\n"
        )

        # Create benchmark masking configuration
        salt = secrets.token_hex(32)
        config = CloakConfig(
            version="1",
            global_settings=GlobalConfig(
                salt=salt,
                cache_pseudonyms=True,
                batch_size=chunk_lines,
            ),
            consistency_groups=[
                ConsistencyGroup(
                    name="cg_users_orders",
                    columns=["users.id", "orders.user_id"],
                    strategy="deterministic_hash",
                    params={"as_integer": True},
                )
            ],
            tables={
                "users": TableRule(
                    columns={
                        "id": ColumnRule(
                            strategy="deterministic_hash",
                            params={"as_integer": True},
                            consistency_group="cg_users_orders",
                        ),
                        "full_name": ColumnRule(
                            strategy="faker", params={"provider": "name", "deterministic": True}
                        ),
                        "email": ColumnRule(
                            strategy="faker", params={"provider": "email", "preserve_domain": True}
                        ),
                        "phone": ColumnRule(strategy="faker", params={"provider": "phone_number"}),
                        "salary": ColumnRule(strategy="jitter", params={"percentage": 10.0}),
                        "ssn": ColumnRule(
                            strategy="pattern_mask", params={"keep_first": 0, "keep_last": 4}
                        ),
                    }
                ),
                "orders": TableRule(
                    columns={
                        "user_id": ColumnRule(
                            strategy="deterministic_hash",
                            params={"as_integer": True},
                            consistency_group="cg_users_orders",
                        ),
                        "amount": ColumnRule(strategy="jitter", params={"percentage": 5.0}),
                        "shipping_address": ColumnRule(
                            strategy="faker", params={"provider": "address"}
                        ),
                        "credit_card": ColumnRule(strategy="credit_card_mask"),
                    }
                ),
            },
        )

        engine = CloakEngine(config)

        # Stream parser selection
        if workers > 1:
            parser = ParallelStreamParser(workers=workers, chunk_lines=chunk_lines)
        else:
            parser = SQLDumpStreamParser()

        console.print("[bold cyan]Streaming & masking dataset...[/bold cyan]")
        tracemalloc.start()
        start_time = time.perf_counter()

        with input_dump.open("r", encoding="utf-8", errors="replace") as in_f:
            with output_dump.open("w", encoding="utf-8", newline="") as out_f:
                parser.process_stream(in_f, out_f, engine)

        duration = max(0.001, time.perf_counter() - start_time)
        current_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        stats = engine.finish()
        mb_per_sec = actual_mb / duration
        rows_per_sec = stats.rows_processed / duration
        peak_mem_mb = peak_mem / (1024 * 1024)

        # Summary Table
        table = Table(
            title="[bold green]Benchmark Performance Results[/bold green]", box=box.ROUNDED
        )
        table.add_column("Metric", style="bold cyan")
        table.add_column("Value", style="bold yellow")

        table.add_row("Input Dataset Size", f"{actual_mb:.2f} MB")
        table.add_row("Rows Processed", f"{stats.rows_processed:,}")
        table.add_row("Cells Masked", f"{stats.cells_masked:,}")
        table.add_row("Total Masking Time", f"{duration:.2f} seconds")
        table.add_row("Throughput (MB/s)", f"[bold green]{mb_per_sec:.2f} MB/s[/bold green]")
        table.add_row(
            "Throughput (Rows/s)", f"[bold green]{rows_per_sec:,.0f} rows/sec[/bold green]"
        )
        table.add_row("Peak Memory (Heap)", f"[bold white]{peak_mem_mb:.2f} MB[/bold white]")
        table.add_row("Worker Concurrency", f"{workers} worker(s)")

        console.print()
        console.print(table)
        console.print()

        return {
            "size_mb": actual_mb,
            "duration_sec": duration,
            "rows_processed": stats.rows_processed,
            "mb_per_sec": mb_per_sec,
            "rows_per_sec": rows_per_sec,
            "peak_mem_mb": peak_mem_mb,
        }


def main():
    parser = argparse.ArgumentParser(description="CloakDB 1GB+ End-to-End Streaming Benchmark")
    parser.add_argument(
        "--size-mb", type=int, default=50, help="Target benchmark dataset size in MB (default: 50)"
    )
    parser.add_argument(
        "--workers", type=int, default=1, help="Parallel worker processes (default: 1)"
    )
    parser.add_argument(
        "--chunk-lines", type=int, default=5000, help="Chunk batch size in lines (default: 5000)"
    )
    parser.add_argument(
        "--sample-only", action="store_true", help="Run a quick 5 MB sample benchmark"
    )

    args = parser.parse_args()
    target_mb = 5 if args.sample_only else args.size_mb
    run_1gb_benchmark(target_size_mb=target_mb, workers=args.workers, chunk_lines=args.chunk_lines)


if __name__ == "__main__":
    main()
