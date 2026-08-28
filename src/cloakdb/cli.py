"""Command Line Interface (CLI) for CloakDB."""

from __future__ import annotations

import secrets
import sys
import time
from pathlib import Path

import typer
from rich import box
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from cloakdb import __version__
from cloakdb.config.loader import load_config, save_config
from cloakdb.config.models import CloakConfig, ColumnRule, GlobalConfig, TableRule
from cloakdb.connectors.live_db import LiveDatabaseConnector
from cloakdb.core.engine import CloakEngine
from cloakdb.parsers.base import BaseStreamParser
from cloakdb.parsers.csv_stream import CSVStreamParser
from cloakdb.parsers.json_stream import JSONLinesStreamParser
from cloakdb.parsers.sql_dump import SQLDumpStreamParser
from cloakdb.scanner.generator import ConfigGenerator
from cloakdb.strategies.registry import StrategyRegistry
from cloakdb.utils.benchmark import run_benchmark
from cloakdb.utils.logger import console, err_console

app = typer.Typer(
    name="cloakdb",
    help="Deterministic database & SQL dump anonymization CLI.",
    add_completion=False,
    no_args_is_help=True,
)


def _version_callback(value: bool) -> None:
    if value:
        console.print(
            f"[bold magenta]CloakDB[/bold magenta] version [bold cyan]{__version__}[/bold cyan]"
        )
        raise typer.Exit()


@app.callback()
def main(
    version: bool | None = typer.Option(
        None,
        "--version",
        "-V",
        help="Show version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """Deterministic database & SQL dump anonymization CLI."""
    pass


@app.command()
def scan(
    target: str = typer.Argument(
        ..., help="Path to SQL dump (.sql), CSV (.csv), or DB connection URL"
    ),
    output: str | None = typer.Option(
        None, "--output", "-o", help="Save generated configuration to YAML file"
    ),
    locale: str = typer.Option(
        "en_US", "--locale", "-l", help="Faker locale (e.g. en_US, tr_TR, de_DE)"
    ),
    max_samples: int = typer.Option(
        500, "--max-samples", "-n", help="Max sample lines/rows to inspect"
    ),
) -> None:
    """Scan a SQL dump, CSV file, or live database to auto-detect PII and generate rules."""
    generator = ConfigGenerator()
    console.print(f"[bold cyan]Scanning target:[/bold cyan] {target}")

    with Progress(
        SpinnerColumn("line"),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing columns and data patterns...", total=None)

        if "://" in target:
            detections = generator.scan_live_db(target, sample_limit=max_samples)
        elif target.endswith(".csv"):
            detections = generator.scan_csv(target, max_rows=max_samples)
        else:
            detections = generator.scan_sql_dump(target, max_lines=max_samples)

        progress.remove_task(task)

    if not detections:
        console.print("[bold yellow]No PII columns detected automatically.[/bold yellow]")
        return

    total_detected_cols = sum(len(cols) for cols in detections.values())
    console.print(
        f"\n[bold green][+] Found {total_detected_cols} sensitive columns across {len(detections)} tables:[/bold green]\n"
    )

    for tbl_name, results in detections.items():
        table = Table(title=f"Table: [bold magenta]{tbl_name}[/bold magenta]", box=box.ROUNDED)
        table.add_column("Column", style="bold cyan")
        table.add_column("Detected PII", style="bold yellow")
        table.add_column("Confidence", justify="right", style="green")
        table.add_column("Recommended Strategy", style="bold white")
        table.add_column("Sample Raw Values", style="dim")

        for res in results:
            samples_str = ", ".join(res.sample_matches[:2])
            conf_str = f"{int(res.confidence * 100)}%"
            table.add_row(
                res.column_name,
                res.pii_type,
                conf_str,
                res.recommended_strategy,
                samples_str or "-",
            )

        console.print(table)
        console.print()

    generated_config = generator.generate_config_from_detections(detections, locale=locale)

    if output:
        out_path = Path(output)
        save_config(generated_config, out_path)
        console.print(
            f"[bold green][+] Generated configuration saved to:[/bold green] [bold white]{out_path.resolve()}[/bold white]"
        )
    else:
        console.print(
            "[dim]Tip: Pass '--output cloakdb.yaml' to save these rules directly to a config file.[/dim]"
        )


@app.command()
def init(
    output: str = typer.Option(
        "cloakdb.yaml", "--output", "-o", help="Target configuration file path"
    ),
    force: bool = typer.Option(
        False, "--force", "-f", help="Overwrite existing configuration file"
    ),
) -> None:
    """Generate a starter CloakDB configuration file with best-practice examples."""
    out_path = Path(output)
    if out_path.exists() and not force:
        err_console.print(
            f"[bold red]Error:[/bold red] '{output}' already exists. Use '--force' to overwrite."
        )
        raise typer.Exit(1)

    template_config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(
            seed=42,
            salt=secrets.token_hex(32),
            locale="en_US",
            batch_size=5000,
            cache_pseudonyms=True,
        ),
        tables={
            "users": TableRule(
                columns={
                    "id": ColumnRule(
                        strategy="deterministic_hash",
                        params={"as_integer": True},
                        consistency_group="user_ids",
                    ),
                    "full_name": ColumnRule(
                        strategy="faker",
                        params={"provider": "name", "deterministic": True},
                    ),
                    "email": ColumnRule(
                        strategy="faker",
                        params={"provider": "email", "preserve_domain": True},
                    ),
                    "phone": ColumnRule(
                        strategy="faker",
                        params={"provider": "phone_number"},
                    ),
                    "credit_card": ColumnRule(
                        strategy="credit_card_mask",
                        params={"mask_char": "*"},
                    ),
                    "ssn": ColumnRule(
                        strategy="pattern_mask",
                        params={"keep_first": 0, "keep_last": 4, "mask_char": "*"},
                    ),
                    "salary": ColumnRule(
                        strategy="jitter",
                        params={"percentage": 10.0, "distribution": "gaussian"},
                    ),
                    "password_hash": ColumnRule(
                        strategy="constant",
                        params={"value_to_set": "argon2$placeholder$masked"},
                    ),
                }
            ),
            "orders": TableRule(
                columns={
                    "user_id": ColumnRule(
                        strategy="deterministic_hash",
                        params={"as_integer": True},
                        consistency_group="user_ids",
                    ),
                    "shipping_address": ColumnRule(
                        strategy="faker",
                        params={"provider": "address"},
                    ),
                }
            ),
        },
    )

    save_config(template_config, out_path)
    console.print(
        f"[bold green][+] Created starter configuration at:[/bold green] [bold white]{out_path.resolve()}[/bold white]"
    )
    console.print(
        "[dim]Customize the rules in this file and run 'cloakdb apply -c cloakdb.yaml -i dump.sql -o masked.sql'[/dim]"
    )


@app.command()
def preview(
    config_file: str = typer.Option(..., "--config", "-c", help="Path to cloakdb.yaml config file"),
    input_file: str = typer.Option(
        ..., "--input", "-i", help="Path to sample SQL dump, CSV, or DB URL"
    ),
    limit: int = typer.Option(5, "--limit", "-n", help="Number of sample records to preview"),
) -> None:
    """Preview side-by-side Before/After masking diffs on sample data."""
    config = load_config(config_file)
    engine = CloakEngine(config)

    console.print(
        f"[bold cyan]Previewing masking transformations with config:[/bold cyan] {config_file}\n"
    )

    if input_file.endswith(".csv"):
        import csv

        with open(input_file, encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if not header:
                return
            first_table = list(config.tables.keys())[0] if config.tables else "default"
            table = Table(title=f"CSV Preview: {first_table}", box=box.ROUNDED)
            table.add_column("Column", style="bold cyan")
            table.add_column("Original Value", style="bold red")
            table.add_column("Masked Value", style="bold green")

            sample_rows = [next(reader, None) for _ in range(limit)]
            for row in sample_rows:
                if row is None:
                    break
                masked = engine.mask_row_values(first_table, header, row)
                for c_name, orig_v, mask_v in zip(header, row, masked):
                    if orig_v != mask_v:
                        table.add_row(c_name, str(orig_v), str(mask_v))
            console.print(table)

    elif "://" in input_file:
        connector = LiveDatabaseConnector(input_file)
        for tbl_name in connector.get_table_names()[:3]:
            rows = connector.fetch_sample_rows(tbl_name, limit=limit)
            if not rows:
                continue
            table = Table(title=f"Live Table: {tbl_name}", box=box.ROUNDED)
            table.add_column("Column", style="bold cyan")
            table.add_column("Original Value", style="bold red")
            table.add_column("Masked Value", style="bold green")

            for r in rows:
                masked_r = engine.mask_record(tbl_name, r)
                for k in r.keys():
                    if r[k] != masked_r[k]:
                        table.add_row(k, str(r[k]), str(masked_r[k]))
            console.print(table)
            console.print()
    else:
        # SQL dump preview
        generator = ConfigGenerator()
        detections = generator.scan_sql_dump(input_file, max_lines=1000)
        table = Table(title="SQL Dump Masking Preview", box=box.ROUNDED)
        table.add_column("Table.Column", style="bold cyan")
        table.add_column("Sample Original", style="bold red")
        table.add_column("Masked Replacement", style="bold green")

        for tbl_name, results in detections.items():
            for res in results:
                for sample in res.sample_matches[:2]:
                    # Mock transformation
                    masked_val = engine.mask_record(tbl_name, {res.column_name: sample}).get(
                        res.column_name
                    )
                    table.add_row(f"{tbl_name}.{res.column_name}", str(sample), str(masked_val))

        console.print(table)


@app.command()
def apply(
    config_file: str = typer.Option(
        ..., "--config", "-c", help="Path to cloakdb.yaml configuration"
    ),
    input_target: str = typer.Option(
        ...,
        "--input",
        "-i",
        help="Input SQL dump (.sql), CSV (.csv), JSONL (.jsonl), or live DB URL",
    ),
    output_target: str | None = typer.Option(
        None, "--output", "-o", help="Output file path (required for file streams)"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Run masking without writing changes"),
    seed: int | None = typer.Option(None, "--seed", "-s", help="Override global seed"),
    locale: str | None = typer.Option(None, "--locale", "-l", help="Override Faker locale"),
    workers: int = typer.Option(
        1, "--workers", "-w", help="Number of parallel worker processes for stream parsing"
    ),
) -> None:
    """Apply masking rules to an input file or live database stream."""
    config = load_config(config_file)
    if seed is not None:
        config.global_settings.seed = seed
    if locale is not None:
        config.global_settings.locale = locale

    engine = CloakEngine(config)

    console.print(
        Panel(
            f"[bold white]CloakDB Masking Engine v{__version__}[/bold white]\n"
            f"[cyan]Config:[/cyan] {config_file}\n"
            f"[cyan]Input:[/cyan] {input_target}\n"
            f"[cyan]Output:[/cyan] {output_target or '[Live In-Place]'}\n"
            f"[cyan]Configured Tables:[/cyan] {len(config.tables)}\n"
            f"[cyan]Workers:[/cyan] {workers}",
            title="[bold green]Execution Plan[/bold green]",
            border_style="green",
        )
    )

    start_time = time.perf_counter()

    # Case 1: Live Database Connection
    if "://" in input_target:
        connector = LiveDatabaseConnector(input_target)
        tables = connector.get_table_names()

        with Progress(
            SpinnerColumn("line"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Masking live database tables...", total=len(tables))

            for tbl in tables:
                if engine.get_table_rule(tbl):
                    progress.update(
                        task, description=f"Masking table [bold magenta]{tbl}[/bold magenta]..."
                    )
                    if not dry_run:
                        connector.mask_table(
                            tbl, engine, batch_size=config.global_settings.batch_size
                        )
                progress.advance(task)

    # Case 2: File Stream (SQL Dump, CSV, JSONL)
    else:
        in_path = Path(input_target)
        if not in_path.exists():
            err_console.print(
                f"[bold red]Error:[/bold red] Input file '{input_target}' does not exist."
            )
            raise typer.Exit(1)

        if not dry_run and not output_target:
            err_console.print(
                "[bold red]Error:[/bold red] Output path (--output / -o) is required for file streams."
            )
            raise typer.Exit(1)

        out_path = Path(output_target) if output_target else None

        # Select stream parser based on extension and worker count
        parser: BaseStreamParser
        if in_path.suffix.lower() == ".csv":
            first_table = list(config.tables.keys())[0] if config.tables else "default"
            parser = CSVStreamParser(table_name=first_table)
        elif in_path.suffix.lower() == ".jsonl":
            first_table = list(config.tables.keys())[0] if config.tables else "default"
            parser = JSONLinesStreamParser(table_name=first_table)
        elif workers > 1:
            from cloakdb.parsers.chunking import ParallelStreamParser

            parser = ParallelStreamParser(workers=workers)
        else:
            parser = SQLDumpStreamParser()

        with Progress(
            SpinnerColumn("line"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(
                f"Streaming and masking [bold cyan]{in_path.name}[/bold cyan]...", total=None
            )

            def _on_progress(rows: int, bytes_processed: int) -> None:
                progress.update(
                    task,
                    description=f"Processed [bold green]{engine.stats.rows_processed:,}[/bold green] rows ({engine.stats.mb_per_second:.1f} MB/s)...",
                )

            with in_path.open("r", encoding="utf-8", errors="replace") as in_stream:
                if dry_run or not out_path:
                    import io

                    null_out = io.StringIO()
                    parser.process_stream(
                        in_stream, null_out, engine, progress_callback=_on_progress
                    )
                else:
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    with out_path.open("w", encoding="utf-8", newline="") as out_stream:
                        parser.process_stream(
                            in_stream, out_stream, engine, progress_callback=_on_progress
                        )

    duration = max(0.001, time.perf_counter() - start_time)
    stats = engine.finish()

    summary_table = Table(box=box.SIMPLE_HEAVY, show_header=False)
    summary_table.add_column("Metric", style="bold cyan")
    summary_table.add_column("Value", style="bold white")
    summary_table.add_row("Status", "[bold green][OK] Completed Successfully[/bold green]")
    summary_table.add_row("Rows Processed", f"{stats.rows_processed:,}")
    summary_table.add_row("Cells Masked", f"{stats.cells_masked:,}")
    summary_table.add_row("Execution Time", f"{duration:.2f} seconds")
    summary_table.add_row(
        "Throughput", f"[bold yellow]{stats.rows_per_second:,.0f} rows/sec[/bold yellow]"
    )

    console.print()
    console.print(
        Panel(summary_table, title="[bold green]Masking Summary[/bold green]", border_style="green")
    )


@app.command()
def strategies() -> None:
    """List all available masking strategies, parameters, and aliases."""
    items = StrategyRegistry.list_strategies()
    table = Table(title="[bold magenta]CloakDB Masking Strategies[/bold magenta]", box=box.ROUNDED)
    table.add_column("Strategy Name", style="bold cyan")
    table.add_column("Aliases", style="yellow")
    table.add_column("Description", style="white")

    for item in items:
        aliases_str = ", ".join(item["aliases"]) if item["aliases"] else "-"
        table.add_row(item["name"], aliases_str, item["description"])

    console.print(table)


@app.command()
def bench(
    rows: int = typer.Option(50000, "--rows", "-n", help="Number of records to benchmark"),
) -> None:
    """Run an in-memory performance and throughput benchmark."""
    console.print(
        f"[bold cyan]Running performance benchmark with {rows:,} multi-column records...[/bold cyan]"
    )
    results = run_benchmark(row_count=rows)

    table = Table(title="[bold green]Benchmark Results[/bold green]", box=box.ROUNDED)
    table.add_column("Metric", style="bold cyan")
    table.add_column("Value", style="bold yellow")

    table.add_row("Records Processed", f"{results['row_count']:,}")
    table.add_row("Columns Per Row", f"{results['columns_per_row']}")
    table.add_row("Total Cells Masked", f"{results['cells_masked']:,}")
    table.add_row("Duration", f"{results['duration_seconds']:.3f} s")
    table.add_row(
        "Throughput (Rows/sec)", f"[bold green]{results['rows_per_sec']:,.0f} rows/sec[/bold green]"
    )
    table.add_row(
        "Throughput (Cells/sec)",
        f"[bold green]{results['cells_per_sec']:,.0f} cells/sec[/bold green]",
    )
    if "peak_memory_mb" in results:
        table.add_row("Peak Memory", f"{results['peak_memory_mb']:.2f} MB")

    console.print(table)


@app.command()
def version() -> None:
    """Show CloakDB version and system details."""
    console.print(
        f"[bold magenta]CloakDB[/bold magenta] version [bold cyan]{__version__}[/bold cyan]"
    )
    console.print(f"Python {sys.version.split()[0]} on {sys.platform}")


if __name__ == "__main__":
    app()
