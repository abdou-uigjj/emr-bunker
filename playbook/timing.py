"""emr-bunker response timing.

The drill's whole point is that detection and response are fast enough to
matter. ProofClock records three wall-clock marks during a tamper response:

    t0_detect          the canary noticed the tamper
    t1_isolated        the engine cut the attacker off
    t2_replica_serving the last-clean snapshot is back, read-only, verified

Marks are first-mark-wins: re-marking never moves a timestamp backwards,
because an incident report that can drift is an incident report a lawyer
can argue with.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

RESPONSE_BUDGET_SECONDS = 60.0

T0_DETECT = "t0_detect"
T1_ISOLATED = "t1_isolated"
T2_REPLICA_SERVING = "t2_replica_serving"

MARK_ORDER = (T0_DETECT, T1_ISOLATED, T2_REPLICA_SERVING)


@dataclass
class ClockReport:
    """Snapshot of one response's timing, safe to serialize."""

    t0_detect: float | None = None
    t1_isolated: float | None = None
    t2_replica_serving: float | None = None
    budget_seconds: float = RESPONSE_BUDGET_SECONDS
    complete: bool = False
    total_seconds: float | None = None
    within_budget: bool = False

    def as_dict(self) -> dict:
        return {
            "t0_detect": self.t0_detect,
            "t1_isolated": self.t1_isolated,
            "t2_replica_serving": self.t2_replica_serving,
            "total_seconds": self.total_seconds,
            "budget_seconds": self.budget_seconds,
            "within_budget": self.within_budget,
            "complete": self.complete,
        }


@dataclass
class ProofClock:
    """Wall-clock witness for one incident response."""

    budget_seconds: float = RESPONSE_BUDGET_SECONDS
    _marks: dict = field(default_factory=dict)

    def _mark(self, name: str) -> float:
        now = time.time()
        return self._marks.setdefault(name, now)

    def detect(self) -> float:
        """T0 - the canary fired."""
        return self._mark(T0_DETECT)

    def isolation_verified(self) -> float:
        """T1 - engine proofs confirm the attacker is locked out."""
        return self._mark(T1_ISOLATED)

    def replica_serving(self) -> float:
        """T2 - the clean replica is up, read-only, and hash-verified."""
        return self._mark(T2_REPLICA_SERVING)

    def mark(self, name: str) -> float:
        """Mark by name (used by the sidecar and tests)."""
        if name not in MARK_ORDER:
            raise ValueError(f"unknown mark {name!r}")
        return self._mark(name)

    def get(self, name: str) -> float | None:
        return self._marks.get(name)

    def report(self) -> ClockReport:
        rep = ClockReport(budget_seconds=self.budget_seconds)
        rep.t0_detect = self._marks.get(T0_DETECT)
        rep.t1_isolated = self._marks.get(T1_ISOLATED)
        rep.t2_replica_serving = self._marks.get(T2_REPLICA_SERVING)
        rep.complete = all(self._marks.get(m) is not None for m in MARK_ORDER)
        if rep.complete:
            rep.total_seconds = round(
                rep.t2_replica_serving - rep.t0_detect, 3
            )
            rep.within_budget = rep.total_seconds <= self.budget_seconds
        else:
            rep.within_budget = False
        return rep
