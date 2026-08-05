"""One shared, deterministic percentile — used by M1's CI and M4's p50/p95.

Kept in one place because the two metrics must agree on what "the 95th
percentile" means: M1 reports a bootstrapped interval at the 2.5/97.5 cut
points and M4 reports p50/p95 latency, and a results file that mixed two
percentile conventions would be quietly incomparable across its own rows.

Pure stdlib.
"""

from __future__ import annotations

from typing import Sequence


def percentile(values: Sequence[float], q: float) -> float:
    """The ``q``-quantile of ``values`` by linear interpolation, ``q`` in [0, 1].

    Uses the inclusive convention (``q=0`` is the minimum, ``q=1`` the maximum,
    interpolating between the two neighbouring order statistics in between) —
    the same definition NumPy's default ``percentile`` and R's type-7 use, so a
    reader comparing these numbers against either gets the same answer.

    Raises ``ValueError`` on an empty sample rather than returning ``0.0``,
    which would read as a real measurement of zero latency.
    """
    if not values:
        raise ValueError("percentile of an empty sample is undefined")
    if not 0.0 <= q <= 1.0:
        raise ValueError(f"quantile must be in [0, 1], got {q!r}")

    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])

    position = q * (len(ordered) - 1)
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    weight = position - low
    return float(ordered[low] + (ordered[high] - ordered[low]) * weight)
