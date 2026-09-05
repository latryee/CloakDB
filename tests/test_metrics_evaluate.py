"""Tests for privacy metric evaluation (k-anonymity, l-diversity, and re-identification risk)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from cloakdb.cli import app
from cloakdb.core.metrics import evaluate_privacy_metrics

runner = CliRunner()


def test_evaluate_privacy_metrics_basic():
    """Test k-anonymity and re-identification risk calculation."""
    # 4 records: 2 share (age=30, zip=10001), 2 share (age=40, zip=20002)
    # k-anonymity should be 2
    records = [
        {"age": "30", "zip": "10001", "diagnosis": "Flu"},
        {"age": "30", "zip": "10001", "diagnosis": "Cold"},
        {"age": "40", "zip": "20002", "diagnosis": "Flu"},
        {"age": "40", "zip": "20002", "diagnosis": "Asthma"},
    ]

    res = evaluate_privacy_metrics(
        records=records,
        quasi_identifiers=["age", "zip"],
        sensitive_attribute="diagnosis",
        threshold_k=2,
        threshold_l=2,
    )

    assert res.total_records == 4
    assert res.num_equivalence_classes == 2
    assert res.k_anonymity == 2
    assert res.records_at_risk == 0
    assert res.l_diversity == 2
    assert res.is_compliant is True
    assert res.re_identification_risk_score == 0.5


def test_evaluate_privacy_metrics_at_risk():
    """Test when dataset contains unique record (k=1) failing threshold."""
    records = [
        {"age": "30", "zip": "10001"},
        {"age": "30", "zip": "10001"},
        {"age": "99", "zip": "99999"},  # Unique outlier!
    ]

    res = evaluate_privacy_metrics(
        records=records,
        quasi_identifiers=["age", "zip"],
        threshold_k=2,
    )

    assert res.k_anonymity == 1
    assert res.records_at_risk == 1
    assert res.is_compliant is False


def test_cli_evaluate_command(tmp_path: Path):
    """Test cloakdb evaluate CLI invocation on CSV file."""
    csv_file = tmp_path / "patients.csv"
    csv_file.write_text(
        "age,zip,gender,diagnosis\n"
        "25,34000,M,Flu\n"
        "25,34000,M,Cold\n"
        "30,35000,F,Flu\n"
        "30,35000,F,Covid\n",
        encoding="utf-8",
    )

    # Compliant check (k=2, l=2)
    result = runner.invoke(
        app,
        [
            "evaluate",
            "-i",
            str(csv_file),
            "--qi",
            "age,zip,gender",
            "-s",
            "diagnosis",
            "-k",
            "2",
            "-l",
            "2",
        ],
    )
    assert result.exit_code == 0
    assert "Mathematical Privacy Evaluation Report" in result.output
    assert "k-Anonymity Score" in result.output
    assert "Privacy Gate Passed" in result.output

    # Non-compliant check (requires k=5)
    result_fail = runner.invoke(
        app,
        ["evaluate", "-i", str(csv_file), "--qi", "age,zip", "-k", "5"],
    )
    assert result_fail.exit_code == 1
    assert "Privacy Gate Failed" in result_fail.output


def test_cli_evaluate_json_output(tmp_path: Path):
    """Test cloakdb evaluate CLI with --json output."""
    csv_file = tmp_path / "data.csv"
    csv_file.write_text("age,city\n20,London\n20,London\n", encoding="utf-8")

    result = runner.invoke(
        app,
        ["evaluate", "-i", str(csv_file), "--qi", "age,city", "-k", "2", "--json"],
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["k_anonymity"] == 2
    assert data["is_compliant"] is True
