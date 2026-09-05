"""Unit tests for GitHub Actions workflow integration, step summaries, and pre-commit hooks."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import yaml

from cloakdb.scanner.detector import PIIDetectionResult
from cloakdb.utils.github import (
    emit_annotation,
    format_masking_summary,
    format_verification_summary,
    is_github_actions,
    write_step_summary,
)


def test_is_github_actions_flag(monkeypatch):
    """Test is_github_actions reflects GITHUB_ACTIONS env var."""
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    assert not is_github_actions()

    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    assert is_github_actions()


def test_write_step_summary(tmp_path: Path, monkeypatch):
    """Test write_step_summary writes markdown to GITHUB_STEP_SUMMARY path."""
    summary_file = tmp_path / "step_summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_file))

    success = write_step_summary("### Test Summary Line")
    assert success is True
    assert summary_file.exists()
    content = summary_file.read_text(encoding="utf-8")
    assert "### Test Summary Line" in content


def test_emit_annotation(monkeypatch, capsys):
    """Test emit_annotation produces correct GitHub Actions workflow commands."""
    monkeypatch.setenv("GITHUB_ACTIONS", "true")

    emit_annotation(
        "Sensitive PII leak detected", title="PII Alert", file="dump.sql", line=42, level="error"
    )
    captured = capsys.readouterr()
    assert (
        "::error file=dump.sql,line=42,title=PII Alert::Sensitive PII leak detected" in captured.out
    )


def test_format_masking_summary():
    """Test format_masking_summary markdown output."""
    stats = MagicMock(
        rows_processed=15000,
        cells_masked=45000,
        elapsed_seconds=1.25,
        mb_per_second=42.5,
    )
    md = format_masking_summary(stats, "dump.sql", "masked.sql", dry_run=False, verified=True)
    assert "## 🛡️ CloakDB Masking Report" in md
    assert "15,000" in md
    assert "masked.sql" in md
    assert "Zero PII Leaks Verified" in md


def test_format_verification_summary():
    """Test format_verification_summary for both clean and leaked datasets."""
    clean_md = format_verification_summary({}, "clean.sql")
    assert "Passed ✅" in clean_md

    leak_detections = {
        "users": [
            PIIDetectionResult(
                column_name="email",
                pii_type="Email",
                confidence=0.99,
                recommended_strategy="email_mask",
                recommended_params={},
                sample_matches=["user@example.com"],
            )
        ]
    }
    leak_md = format_verification_summary(leak_detections, "dirty.sql")
    assert "FAILED ❌" in leak_md
    assert "| `users` | `email` | `Email` | `99%` |" in leak_md


def test_pre_commit_hooks_yaml_validity():
    """Validates that .pre-commit-hooks.yaml exists and parses as valid config."""
    hook_path = Path(__file__).resolve().parent.parent / ".pre-commit-hooks.yaml"
    assert hook_path.exists()

    data = yaml.safe_load(hook_path.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    assert len(data) >= 1
    assert data[0]["id"] == "cloakdb-lint"
    assert data[0]["entry"] == "cloakdb lint"
