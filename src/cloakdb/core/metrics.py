"""Privacy metric evaluation engine: k-anonymity, l-diversity, and re-identification risk."""

from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class PrivacyEvaluationResult:
    """Mathematical privacy evaluation metrics for a dataset."""

    total_records: int
    num_quasi_identifiers: int
    quasi_identifiers: list[str]
    sensitive_attribute: str | None
    num_equivalence_classes: int
    k_anonymity: int
    avg_equivalence_class_size: float
    records_at_risk: int
    records_at_risk_percent: float
    re_identification_risk_score: float
    max_re_identification_risk: float
    l_diversity: int | None = None
    l_diversity_distribution: dict[int, int] | None = None
    is_compliant: bool = True
    threshold_k: int = 5
    threshold_l: int = 2

    def to_dict(self) -> dict[str, Any]:
        """Converts results to a serializable dictionary."""
        return {
            "total_records": self.total_records,
            "quasi_identifiers": self.quasi_identifiers,
            "sensitive_attribute": self.sensitive_attribute,
            "num_equivalence_classes": self.num_equivalence_classes,
            "k_anonymity": self.k_anonymity,
            "avg_equivalence_class_size": round(self.avg_equivalence_class_size, 2),
            "records_at_risk": self.records_at_risk,
            "records_at_risk_percent": round(self.records_at_risk_percent, 2),
            "re_identification_risk_score": round(self.re_identification_risk_score, 4),
            "max_re_identification_risk": round(self.max_re_identification_risk, 4),
            "l_diversity": self.l_diversity,
            "threshold_k": self.threshold_k,
            "threshold_l": self.threshold_l,
            "is_compliant": self.is_compliant,
        }


def evaluate_privacy_metrics(
    records: Iterable[dict[str, Any]],
    quasi_identifiers: Sequence[str],
    sensitive_attribute: str | None = None,
    threshold_k: int = 5,
    threshold_l: int = 2,
) -> PrivacyEvaluationResult:
    """Evaluates k-anonymity, l-diversity, and re-identification risk metrics.

    Args:
        records: Stream or list of record dictionaries.
        quasi_identifiers: Column names forming the quasi-identifier tuple.
        sensitive_attribute: Optional sensitive attribute column for l-diversity.
        threshold_k: Target k-anonymity compliance threshold.
        threshold_l: Target l-diversity compliance threshold.
    """
    qi_list = list(quasi_identifiers)
    if not qi_list:
        raise ValueError("At least one quasi-identifier column must be specified.")

    # Group records into equivalence classes
    ec_counts: Counter[tuple[Any, ...]] = Counter()
    ec_sensitive_values: defaultdict[tuple[Any, ...], set[Any]] = defaultdict(set)
    total_records = 0

    for rec in records:
        total_records += 1
        qi_key = tuple(str(rec.get(col, "")) for col in qi_list)
        ec_counts[qi_key] += 1

        if sensitive_attribute:
            sens_val = rec.get(sensitive_attribute)
            if sens_val is not None:
                ec_sensitive_values[qi_key].add(str(sens_val))

    if total_records == 0:
        return PrivacyEvaluationResult(
            total_records=0,
            num_quasi_identifiers=len(qi_list),
            quasi_identifiers=qi_list,
            sensitive_attribute=sensitive_attribute,
            num_equivalence_classes=0,
            k_anonymity=0,
            avg_equivalence_class_size=0.0,
            records_at_risk=0,
            records_at_risk_percent=0.0,
            re_identification_risk_score=0.0,
            max_re_identification_risk=0.0,
            l_diversity=None,
            is_compliant=True,
            threshold_k=threshold_k,
            threshold_l=threshold_l,
        )

    num_classes = len(ec_counts)
    class_sizes = list(ec_counts.values())
    k_min = min(class_sizes) if class_sizes else 0
    avg_size = total_records / num_classes if num_classes > 0 else 0.0

    # Records at risk (k < threshold_k)
    records_at_risk = sum(count for count in class_sizes if count < threshold_k)
    risk_percent = (records_at_risk / total_records) * 100.0 if total_records > 0 else 0.0

    # Average re-identification risk = sum of (1 / |EC_i|) * (size / N) = num_classes / N
    re_id_risk = num_classes / total_records if total_records > 0 else 0.0
    max_risk = (1.0 / k_min) if k_min > 0 else 1.0

    # l-diversity
    min_l: int | None = None
    l_dist: dict[int, int] | None = None
    if sensitive_attribute:
        distinct_counts = [len(s) for s in ec_sensitive_values.values()]
        min_l = min(distinct_counts) if distinct_counts else 0
        l_counter = Counter(distinct_counts)
        l_dist = dict(sorted(l_counter.items()))

    # Compliance check: k >= threshold_k and (if sensitive) l >= threshold_l
    is_compliant = k_min >= threshold_k
    if sensitive_attribute and min_l is not None:
        is_compliant = is_compliant and (min_l >= threshold_l)

    return PrivacyEvaluationResult(
        total_records=total_records,
        num_quasi_identifiers=len(qi_list),
        quasi_identifiers=qi_list,
        sensitive_attribute=sensitive_attribute,
        num_equivalence_classes=num_classes,
        k_anonymity=k_min,
        avg_equivalence_class_size=avg_size,
        records_at_risk=records_at_risk,
        records_at_risk_percent=risk_percent,
        re_identification_risk_score=re_id_risk,
        max_re_identification_risk=max_risk,
        l_diversity=min_l,
        l_diversity_distribution=l_dist,
        is_compliant=is_compliant,
        threshold_k=threshold_k,
        threshold_l=threshold_l,
    )


def load_records_from_file(
    file_path: str | Path,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Loads row dictionaries from CSV, JSON, JSONL, or Parquet files for evaluation."""
    p = Path(file_path)
    if not p.exists():
        raise FileNotFoundError(f"File '{file_path}' does not exist.")

    ext = p.suffix.lower()
    records: list[dict[str, Any]] = []

    if ext == ".csv":
        with open(p, encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                records.append(dict(row))
                if limit and len(records) >= limit:
                    break
    elif ext == ".jsonl":
        with open(p, encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.strip():
                    records.append(json.loads(line))
                    if limit and len(records) >= limit:
                        break
    elif ext == ".json":
        with open(p, encoding="utf-8", errors="replace") as f:
            data = json.load(f)
            if isinstance(data, list):
                records = data[:limit] if limit else data
            elif isinstance(data, dict):
                records = [data]
    elif ext == ".parquet":
        try:
            import pyarrow.parquet as pq

            table = pq.read_table(p)
            for batch in table.to_batches():
                records.extend(batch.to_pylist())
                if limit and len(records) >= limit:
                    records = records[:limit]
                    break
        except ImportError as e:
            raise RuntimeError(
                "pyarrow is required to read Parquet files. Install with `pip install pyarrow`."
            ) from e
    else:
        # Fallback for simple key-value extraction or text lines
        with open(p, encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.strip():
                    records.append({"line": line.strip()})
                    if limit and len(records) >= limit:
                        break

    return records
