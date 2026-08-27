"""Console output formatting and logging using Rich."""

from __future__ import annotations

import logging
import sys

from rich.console import Console
from rich.logging import RichHandler
from rich.theme import Theme

# Reconfigure standard streams to UTF-8 on Windows if possible
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

custom_theme = Theme(
    {
        "info": "cyan",
        "warning": "yellow",
        "danger": "bold red",
        "success": "bold green",
        "header": "bold magenta",
        "key": "bold blue",
        "value": "bold white",
    }
)

console = Console(theme=custom_theme, safe_box=True)
err_console = Console(theme=custom_theme, stderr=True, safe_box=True)


def setup_logging(verbose: bool = False) -> None:
    """Configures root logging with RichHandler."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True, show_path=False)],
    )
