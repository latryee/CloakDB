"""GitHub Actions workflow helpers, annotations, and step summary generation."""

from __future__ import annotations

import os
from typing import Any


def is_github_actions() -> bool:
    """Returns True if running inside a GitHub Actions runner environment."""
    return os.getenv("GITHUB_ACTIONS") == "true"


def write_step_summary(content: str, append: bool = True) -> bool:
    """Writes Markdown content to the GITHUB_STEP_SUMMARY file if present."""
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return False

    try:
        mode = "a" if append else "w"
        with open(summary_path, mode, encoding="utf-8") as f:
            f.write(content.strip() + "\n\n")
        return True
    except OSError:
        return False


def emit_annotation(
    message: str,
    title: str | None = None,
    file: str | None = None,
    line: int | None = None,
    col: int | None = None,
    level: str = "error",
) -> None:
    """Emits GitHub Actions workflow command annotations (::error, ::warning, ::notice)."""
    if not is_github_actions():
        return

    params: list[str] = []
    if file:
        params.append(f"file={file}")
    if line:
        params.append(f"line={line}")
    if col:
        params.append(f"col={col}")
    if title:
        params.append(f"title={title}")

    param_str = f" {','.join(params)}" if params else ""
    # Format: ::error file=app.js,line=1::Missing semicolon
    clean_msg = message.replace("\r", "").replace("\n", "%0A")
    print(f"::{level}{param_str}::{clean_msg}", flush=True)


def format_masking_summary(
    stats: Any,
    input_path: str,
    output_path: str | None,
    dry_run: bool = False,
    verified: bool | None = None,
) -> str:
    """Generates a GitHub Actions Step Summary markdown report for masking runs."""
    status_badge = "🛡️ **Masking Succeeded**" if not dry_run else "🧪 **Dry Run Completed**"
    verified_badge = (
        "✅ **Zero PII Leaks Verified**"
        if verified is True
        else ("⚠️ **Unverified**" if verified is None else "❌ **Leak Detected**")
    )

    rows = getattr(stats, "rows_processed", 0)
    cells = getattr(stats, "cells_masked", 0)
    duration = getattr(stats, "elapsed_seconds", 0.0)
    mb_s = getattr(stats, "mb_per_second", 0.0)

    return f"""## 🛡️ CloakDB Masking Report

| Metric | Details |
| :--- | :--- |
| **Status** | {status_badge} |
| **Verification** | {verified_badge} |
| **Input Dataset** | `{input_path}` |
| **Output Dataset** | `{output_path or "N/A (Dry Run)"}` |
| **Rows Processed** | `{rows:,}` |
| **Cells Masked** | `{cells:,}` |
| **Throughput** | `{mb_s:.2f} MB/s` |
| **Elapsed Time** | `{duration:.2f} s` |

> *CloakDB deterministic anonymization performed with $\\mathcal{{O}}(1)$ streaming memory.*
"""


def format_verification_summary(
    detections: dict[str, list[Any]],
    target: str,
) -> str:
    """Generates a GitHub Actions Step Summary for PII verification audits."""
    if not detections:
        return f"""## 🛡️ CloakDB Zero-PII Verification: Passed ✅

**Target Dataset:** `{target}`

- **Status:** All cryptographic checksums (Luhn, TCKN, IBAN) and regex heuristics passed.
- **Leaked PII Count:** `0` unmasked sensitive records detected.
- **Compliance:** Ready for staging, testing, or analytics export.
"""

    total_leaks = sum(len(items) for items in detections.values())
    rows_md = []
    for tbl, items in detections.items():
        for res in items:
            conf = f"{int(res.confidence * 100)}%"
            rows_md.append(f"| `{tbl}` | `{res.column_name}` | `{res.pii_type}` | `{conf}` |")

    table_body = "\n".join(rows_md)

    return f"""## ⚠️ CloakDB Zero-PII Verification: FAILED ❌

**Target Dataset:** `{target}`
**Total Unmasked Sensitive Columns:** `{total_leaks}`

| Table | Column | Detected PII | Confidence |
| :--- | :--- | :--- | :--- |
{table_body}

> **Action Required:** Update your `cloakdb.yaml` policy with masking rules for the columns above.
"""
