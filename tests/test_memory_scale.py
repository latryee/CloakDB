"""Unit tests validating constant O(1) memory scaling across data volumes."""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.profile_memory import profile_memory_at_tier


def test_constant_memory_scaling():
    """Validates that peak heap memory remains virtually flat when scaling row count by 10x."""
    res_1k = profile_memory_at_tier(1000)
    res_10k = profile_memory_at_tier(10000)

    # Memory difference between 1k and 10k rows must be minimal (< 5 MB variance)
    mem_delta = abs(res_10k["peak_mem_mb"] - res_1k["peak_mem_mb"])
    assert mem_delta < 5.0, (
        f"Memory scaling exceeded constant O(1) bound: 1k={res_1k['peak_mem_mb']:.2f}MB, "
        f"10k={res_10k['peak_mem_mb']:.2f}MB (delta={mem_delta:.2f}MB)"
    )

    # Both tiers must stay well below 40 MB peak memory
    assert res_1k["peak_mem_mb"] < 40.0
    assert res_10k["peak_mem_mb"] < 40.0
