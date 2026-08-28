"""Command Line Interface (CLI) for CloakDB."""

from __future__ import annotations

import secrets
import sys
import time
from pathlib import Path
from typing import Any

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
from cloakdb.utils.security import (
    compute_salt_fingerprint,
    is_insecure_salt,
    is_production_connection,
    redact_connection_url,
)

app = typer.Typer(
    name="cloakdb",
    help="Deterministic database & SQL dump anonymization CLI.",
    add_completion=False,
    no_args_is_help=True,
)


def _check_salt_security(salt: str | None, allow_insecure_salt: bool = False) -> None:
    """Verifies that the provided salt meets cryptographic complexity requirements."""
    is_weak, reason = is_insecure_salt(salt)
    if is_weak:
        warning_msg = (
            "[bold red]CRITICAL SECURITY WARNING: INSECURE / DEFAULT SALT DETECTED[/bold red]\n\n"
            f"[yellow]Reason: {reason}[/yellow]\n\n"
            "Using a default or weak salt exposes HMAC pseudonyms to brute-force\n"
            "and rainbow table precomputation attacks!\n"
            "In production environments, ensure you configure a cryptographically secure\n"
            "salt (at least 32 characters), preferably via an environment variable."
        )
        err_console.print(
            Panel(warning_msg, title="[bold red]SECURITY ALERT[/bold red]", border_style="red")
        )

        if not allow_insecure_salt:
            err_console.print(
                "[bold red]Error:[/bold red] Execution aborted due to insecure salt. "
                "Pass '--allow-insecure-salt' to bypass this check."
            )
            raise typer.Exit(1)


def _check_salt_fingerprint(
    config: CloakConfig,
    ignore_salt_mismatch: bool = False,
    update_salt_fingerprint: bool = False,
    config_path: str | Path | None = None,
) -> None:
    """Verifies salt fingerprint to prevent accidental foreign key consistency breaks across runs."""
    configured_fp = config.global_settings.salt_fingerprint
    if not configured_fp:
        return

    active_fp = config.global_settings.compute_fingerprint()
    if configured_fp != active_fp:
        if update_salt_fingerprint and config_path:
            config.global_settings.salt_fingerprint = active_fp
            save_config(config, config_path)
            console.print(
                f"[bold green][+] Salt fingerprint updated to '{active_fp}' in configuration.[/bold green]"
            )
            return

        warning_msg = (
            "[bold yellow]CRITICAL WARNING: SALT ROTATION / MISMATCH DETECTED[/bold yellow]\n\n"
            f"Configured Salt Fingerprint: [cyan]{configured_fp}[/cyan]\n"
            f"Active Salt Fingerprint:     [red]{active_fp}[/red]\n\n"
            "Foreign key referential integrity across previous masking batches or consistency groups\n"
            "will be BROKEN because the salt has changed!"
        )
        err_console.print(
            Panel(warning_msg, title="[bold yellow]INTEGRITY WARNING[/bold yellow]", border_style="yellow")
        )

        if not ignore_salt_mismatch:
            err_console.print(
                "[bold red]Error:[/bold red] Salt fingerprint mismatch. "
                "Pass '--ignore-salt-mismatch' to proceed anyway, or '--update-salt-fingerprint' to re-bind."
            )
            raise typer.Exit(1)


def _check_production_safety(target: str, confirm_production: bool = False) -> None:
    """Detects live production database targets and demands explicit confirmation."""
    if is_production_connection(target):
        warning_msg = (
            "[bold red]PRODUCTION DATABASE TARGET DETECTED[/bold red]\n\n"
            f"Target URL: [yellow]{redact_connection_url(target)}[/yellow]\n\n"
            "You are attempting to execute in-place masking on a LIVE PRODUCTION database.\n"
            "This operation will directly modify records in the target database!"
        )
        err_console.print(
            Panel(warning_msg, title="[bold red]PRODUCTION GUARD[/bold red]", border_style="red")
        )

        if not confirm_production:
            if sys.stdin.isatty():
                confirmed = typer.confirm(
                    "Are you sure you want to perform in-place masking on this PRODUCTION database?",
                    default=False,
                )
                if not confirmed:
                    err_console.print("[bold red]Aborted by user.[/bold red]")
                    raise typer.Exit(1)
            else:
                err_console.print(
                    "[bold red]Error:[/bold red] Production database detected in non-interactive mode. "
                    "You must supply '--confirm-production' to execute."
                )
                raise typer.Exit(1)


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
    infer_fks: bool = typer.Option(
        False, "--infer-fks", help="Infer foreign key relationships and generate consistency groups"
    ),
    allow_insecure_salt: bool = typer.Option(
        False, "--allow-insecure-salt", help="Allow running with weak/default salt"
    ),
) -> None:
    """Scan a SQL dump, CSV file, or live database to auto-detect PII and generate rules."""
    generator = ConfigGenerator()
    console.print(f"[bold cyan]Scanning target:[/bold cyan] {redact_connection_url(target)}")

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

    if not detections and not infer_fks:
        console.print("[bold yellow]No PII columns detected automatically.[/bold yellow]")
        return

    if detections:
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

    generated_config = generator.generate_config_from_detections(
        detections, locale=locale, target=target if infer_fks else None, infer_fks=infer_fks
    )

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

    random_salt = secrets.token_hex(32)
    template_config = CloakConfig(
        version="1",
        global_settings=GlobalConfig(
            seed=42,
            salt=random_salt,
            salt_fingerprint=compute_salt_fingerprint(random_salt),
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
    allow_insecure_salt: bool = typer.Option(
        False, "--allow-insecure-salt", help="Allow running with weak/default salt"
    ),
) -> None:
    """Preview side-by-side Before/After masking diffs on sample data."""
    config = load_config(config_file)
    _check_salt_security(config.global_settings.salt, allow_insecure_salt=allow_insecure_salt)
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
    allow_insecure_salt: bool = typer.Option(
        False, "--allow-insecure-salt", help="Allow execution even if a weak/default salt is used"
    ),
    confirm_production: bool = typer.Option(
        False, "--confirm-production", help="Explicitly confirm applying in-place masking to production DB"
    ),
    ignore_salt_mismatch: bool = typer.Option(
        False, "--ignore-salt-mismatch", help="Ignore salt fingerprint mismatch warning/error"
    ),
    update_salt_fingerprint: bool = typer.Option(
        False, "--update-salt-fingerprint", help="Re-compute and update salt fingerprint in config file"
    ),
    stateless: bool = typer.Option(
        False, "--stateless", help="Run with O(1) stateless memory mode (no LRU cache)"
    ),
    since: str | None = typer.Option(
        None, "--since", help="Incremental timestamp lower bound (e.g. 2026-01-01T00:00:00)"
    ),
    incremental_column: str | None = typer.Option(
        None, "--incremental-column", help="Column name to check for incremental threshold"
    ),
) -> None:
    """Apply masking rules to an input file or live database stream."""
    config = load_config(config_file)
    _check_salt_security(config.global_settings.salt, allow_insecure_salt=allow_insecure_salt)
    _check_salt_fingerprint(
        config,
        ignore_salt_mismatch=ignore_salt_mismatch,
        update_salt_fingerprint=update_salt_fingerprint,
        config_path=config_file,
    )
    _check_production_safety(input_target, confirm_production=confirm_production)

    if seed is not None:
        config.global_settings.seed = seed
    if locale is not None:
        config.global_settings.locale = locale
    if stateless:
        config.global_settings.stateless = True
        config.global_settings.cache_pseudonyms = False

    engine = CloakEngine(
        config,
        incremental_since=since,
        incremental_column=incremental_column,
    )

    console.print(
        Panel(
            f"[bold white]CloakDB Masking Engine v{__version__}[/bold white]\n"
            f"[cyan]Config:[/cyan] {config_file}\n"
            f"[cyan]Input:[/cyan] {redact_connection_url(input_target)}\n"
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
                f"[bold red]Error:[/bold red] Input file '{redact_connection_url(input_target)}' does not exist."
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
            if workers > 1:
                console.print(
                    f"[bold yellow]Warning:[/bold yellow] Parallel processing (--workers {workers}) is not yet supported for CSV files. Falling back to single-worker mode."
                )
            first_table = list(config.tables.keys())[0] if config.tables else "default"
            parser = CSVStreamParser(table_name=first_table)
        elif in_path.suffix.lower() == ".jsonl":
            if workers > 1:
                console.print(
                    f"[bold yellow]Warning:[/bold yellow] Parallel processing (--workers {workers}) is not yet supported for JSONL files. Falling back to single-worker mode."
                )
            first_table = list(config.tables.keys())[0] if config.tables else "default"
            parser = JSONLinesStreamParser(table_name=first_table)
        elif in_path.suffix.lower() == ".json":
            if workers > 1:
                console.print(
                    f"[bold yellow]Warning:[/bold yellow] Parallel processing (--workers {workers}) is not yet supported for JSON document files. Falling back to single-worker mode."
                )
            first_table = list(config.tables.keys())[0] if config.tables else "default"
            from cloakdb.parsers.json_stream import JSONDocumentStreamParser

            parser = JSONDocumentStreamParser(table_name=first_table)
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
def verify(
    target: str = typer.Option(
        ...,
        "--input",
        "-i",
        help="Path to masked SQL dump (.sql), CSV (.csv), JSONL (.jsonl), or live DB URL",
    ),
    config_file: str | None = typer.Option(
        None, "--config", "-c", help="Optional path to cloakdb.yaml to verify mapped rules"
    ),
    max_samples: int = typer.Option(
        1000, "--max-samples", "-n", help="Number of sample lines/rows to inspect"
    ),
    allow_insecure_salt: bool = typer.Option(
        False, "--allow-insecure-salt", help="Allow running with weak/default salt"
    ),
) -> None:
    """Verify masked output datasets to ensure zero real PII remains (CI/CD audit)."""
    if config_file:
        config = load_config(config_file)
        _check_salt_security(config.global_settings.salt, allow_insecure_salt=allow_insecure_salt)

    generator = ConfigGenerator()
    console.print(
        f"[bold cyan]Auditing dataset for unmasked PII:[/bold cyan] {redact_connection_url(target)}"
    )

    with Progress(
        SpinnerColumn("line"),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning dataset with multi-layer PII detector...", total=None)

        if "://" in target:
            detections = generator.scan_live_db(target, sample_limit=max_samples, data_only=True)
        elif target.endswith(".csv"):
            detections = generator.scan_csv(target, max_rows=max_samples, data_only=True)
        else:
            detections = generator.scan_sql_dump(target, max_lines=max_samples, data_only=True)

        progress.remove_task(task)

    if not detections:
        console.print()
        console.print(
            Panel(
                "[bold green][PASS] ZERO UNMASKED PII DETECTED[/bold green]\n\n"
                "The scanned dataset passed all cryptographic checksums and regex heuristics.\n"
                "No raw credit cards (Luhn-valid), TCKN IDs, plaintext emails, or unmasked credentials were found.\n"
                "Dataset is verified compliant for GDPR/KVKK/HIPAA export.",
                title="[bold green]CloakDB Verification Report[/bold green]",
                border_style="green",
            )
        )
        return

    # Found potential leaks!
    total_detected = sum(len(cols) for cols in detections.values())
    table = Table(
        title="[bold red]VERIFICATION FAILED: Unmasked PII Found in Dataset[/bold red]",
        box=box.HEAVY_EDGE,
    )
    table.add_column("Table", style="bold magenta")
    table.add_column("Column", style="bold cyan")
    table.add_column("Leaked PII Type", style="bold red")
    table.add_column("Confidence", justify="right", style="yellow")
    table.add_column("Sample Raw Values", style="white")

    for tbl_name, results in detections.items():
        for res in results:
            samples_str = ", ".join(res.sample_matches[:2])
            conf_str = f"{int(res.confidence * 100)}%"
            table.add_row(
                tbl_name,
                res.column_name,
                res.pii_type,
                conf_str,
                samples_str or "-",
            )

    console.print()
    console.print(table)
    console.print()
    err_console.print(
        Panel(
            f"[bold red][FAIL] {total_detected} sensitive column(s) contain unmasked PII.[/bold red]\n"
            "Review your cloakdb.yaml configuration and re-apply masking before distributing this data.",
            title="[bold red]Audit Status: Non-Compliant[/bold red]",
            border_style="red",
        )
    )
    raise typer.Exit(1)


@app.command()
def diff(
    config_1: str = typer.Option(
        ..., "--config-1", "-c1", help="Path to base cloakdb.yaml configuration"
    ),
    config_2: str = typer.Option(
        ..., "--config-2", "-c2", help="Path to comparative cloakdb.yaml configuration"
    ),
    input_target: str = typer.Option(
        ..., "--input", "-i", help="Sample input file (.csv, .json, .jsonl, .sql) or live DB URL"
    ),
    limit: int = typer.Option(5, "--limit", "-n", help="Number of sample rows to compare"),
) -> None:
    """Compare masking outputs side-by-side between two CloakDB configurations."""
    cfg1 = load_config(config_1)
    cfg2 = load_config(config_2)
    engine1 = CloakEngine(cfg1)
    engine2 = CloakEngine(cfg2)

    console.print(
        Panel(
            f"[bold cyan]Comparing Masking Outputs:[/bold cyan]\n"
            f"[bold]Config A:[/bold] {config_1}\n"
            f"[bold]Config B:[/bold] {config_2}\n"
            f"[bold]Dataset:[/bold]  {redact_connection_url(input_target)}",
            title="[bold green]CloakDB Config Diff[/bold green]",
            border_style="green",
        )
    )

    sample_records: list[tuple[str, dict[str, Any]]] = []
    if "://" in input_target:
        connector = LiveDatabaseConnector(input_target)
        for tbl in connector.get_table_names()[:3]:
            for r in connector.fetch_sample_rows(tbl, limit=limit):
                sample_records.append((tbl, r))
    elif input_target.endswith(".csv"):
        import csv

        with open(input_target, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            first_tbl = list(cfg1.tables.keys())[0] if cfg1.tables else "default"
            for row in list(reader)[:limit]:
                sample_records.append((first_tbl, row))
    elif input_target.endswith(".jsonl"):
        import json

        with open(input_target, "r", encoding="utf-8", errors="replace") as f:
            first_tbl = list(cfg1.tables.keys())[0] if cfg1.tables else "default"
            for line in f:
                if line.strip():
                    sample_records.append((first_tbl, json.loads(line)))
                    if len(sample_records) >= limit:
                        break
    elif input_target.endswith(".json"):
        import json

        with open(input_target, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
            first_tbl = list(cfg1.tables.keys())[0] if cfg1.tables else "default"
            if isinstance(data, list):
                for item in data[:limit]:
                    if isinstance(item, dict):
                        sample_records.append((first_tbl, item))
            elif isinstance(data, dict):
                sample_records.append((first_tbl, data))
    else:
        # SQL dump
        generator = ConfigGenerator()
        detections = generator.scan_sql_dump(input_target, max_lines=500)
        for tbl, res_list in detections.items():
            for res in res_list:
                for s in res.sample_matches[:limit]:
                    sample_records.append((tbl, {res.column_name: s}))

    if not sample_records:
        console.print("[bold yellow]No sample records found to compare.[/bold yellow]")
        return

    table = Table(title="[bold green]Side-by-Side Masking Output Diff[/bold green]", box=box.ROUNDED)
    table.add_column("Table.Column", style="bold cyan")
    table.add_column("Original Value", style="bold white")
    table.add_column("Config A Output", style="bold yellow")
    table.add_column("Config B Output", style="bold green")
    table.add_column("Diff Status", style="bold magenta")

    diff_count = 0
    total_comparisons = 0

    for tbl_name, rec in sample_records:
        masked1 = engine1.mask_record(tbl_name, rec)
        masked2 = engine2.mask_record(tbl_name, rec)

        for col in rec.keys():
            orig_v = rec[col]
            v1 = masked1.get(col, orig_v)
            v2 = masked2.get(col, orig_v)
            if v1 != orig_v or v2 != orig_v:
                total_comparisons += 1
                if v1 != v2:
                    diff_count += 1
                    status = "[bold red]CHANGED[/bold red]"
                else:
                    status = "[dim green]IDENTICAL[/dim green]"
                table.add_row(f"{tbl_name}.{col}", str(orig_v), str(v1), str(v2), status)

    console.print()
    console.print(table)
    console.print()
    console.print(
        f"Summary: [bold cyan]{total_comparisons}[/bold cyan] masked cell(s) compared, "
        f"[bold yellow]{diff_count}[/bold yellow] differing value(s) between configs.\n"
    )


@app.command()
def version() -> None:
    """Show CloakDB version and system details."""
    console.print(
        f"[bold magenta]CloakDB[/bold magenta] version [bold cyan]{__version__}[/bold cyan]"
    )
    console.print(f"Python {sys.version.split()[0]} on {sys.platform}")


if __name__ == "__main__":
    app()
