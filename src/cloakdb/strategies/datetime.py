"""Date and time anonymization strategies."""

from __future__ import annotations

import random
from datetime import date, datetime, timedelta
from typing import Any

from cloakdb.core.context import TransformationContext
from cloakdb.strategies.base import MaskingStrategy
from cloakdb.strategies.registry import register_strategy


def _parse_datetime(val: Any) -> datetime | date | None:
    """Attempts to parse string/date/datetime inputs flexibly."""
    if isinstance(val, (datetime, date)):
        return val
    if not isinstance(val, str):
        return None

    val_str = val.strip()
    # Try ISO formats
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d",
    ):
        try:
            return datetime.strptime(val_str, fmt)
        except ValueError:
            continue

    try:
        return datetime.fromisoformat(val_str)
    except (ValueError, TypeError):
        return None


@register_strategy("date_shift", aliases=["shift_date", "date_offset"])
class DateShiftStrategy(MaskingStrategy):
    """Shifts dates forwards or backwards by a bounded random or deterministic interval."""

    description = "Shifts dates by +/- delta days (maintains chronological consistency)"

    def transform(
        self,
        value: Any,
        context: TransformationContext,
        *,
        max_days_forward: int = 30,
        max_days_backward: int = 30,
        preserve_day_of_week: bool = False,
        deterministic: bool = True,
        **kwargs: Any,
    ) -> Any:
        if value is None:
            return None

        dt = _parse_datetime(value)
        if dt is None:
            return value

        rng = random.Random()
        if deterministic:
            rng.seed(context.derive_seed(value))

        offset_days = rng.randint(-max_days_backward, max_days_forward)

        if preserve_day_of_week:
            # Round offset to nearest multiple of 7
            offset_days = (offset_days // 7) * 7

        shifted = dt + timedelta(days=offset_days)

        if isinstance(value, str):
            if isinstance(dt, datetime) and " " in value:
                return shifted.strftime("%Y-%m-%d %H:%M:%S")
            elif "T" in value:
                return shifted.isoformat()
            return shifted.strftime("%Y-%m-%d")

        return shifted


@register_strategy("date_truncate", aliases=["truncate_date", "generalize_date"])
class DateTruncateStrategy(MaskingStrategy):
    """Truncates dates to month or year level for k-anonymity privacy guarantees."""

    description = "Truncates dates to Year or Month (e.g. '1995-04-12' -> '1995-01-01')"

    def transform(
        self,
        value: Any,
        context: TransformationContext,
        *,
        level: str = "year",
        **kwargs: Any,
    ) -> Any:
        if value is None:
            return None

        dt = _parse_datetime(value)
        if dt is None:
            return value

        if level == "year":
            truncated = dt.replace(month=1, day=1)
        elif level == "month":
            truncated = dt.replace(day=1)
        else:
            truncated = dt

        if isinstance(value, str):
            return truncated.strftime("%Y-%m-%d")
        return truncated
