"""The response playbook - one template, every engine.

When the canary fires, on_tamper() runs five moves in order:

  1. incident seal   - the trigger evidence is sealed into the vault
  2. isolate         - the engine cuts the attacker off
  3. prove severance - engine proofs must show the lockout is real
  4. restore         - the last-clean 'baseline' seal is restored into a
                       break-glass read-only replica
  5. prove serving   - the replica is hash-verified and read-only

Every step emits Proof objects, and the clock is marked as each phase
lands. The report is only ok when every proof passes AND the whole run
fits inside RESPONSE_BUDGET_SECONDS.

The 'refusing to guess' rule lives here: if the vault holds no 'baseline'
seal, the responder stops instead of restoring some snapshot it cannot
vouch for.
"""

from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from .timing import ProofClock


@dataclass
class Proof:
    """One checkable claim about the response."""

    name: str
    passed: bool
    detail: str = ""

    def as_dict(self) -> dict:
        return {"name": self.name, "passed": self.passed,
                "detail": self.detail}


@dataclass
class ResponseReport:
    """The verdict of one on_tamper() run."""

    proofs: list = field(default_factory=list)
    clock: ProofClock | None = None

    @property
    def all_proofs_passed(self) -> bool:
        return bool(self.proofs) and all(p.passed for p in self.proofs)

    @property
    def within_budget(self) -> bool:
        return bool(self.clock and self.clock.report().within_budget)

    @property
    def ok(self) -> bool:
        return self.all_proofs_passed and self.within_budget

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "proofs": [p.as_dict() for p in self.proofs],
            "clock": self.clock.report().as_dict() if self.clock else None,
        }


def incident_label(vault=None) -> str:
    """Collision-safe incident seal label (one per tamper, in order)."""
    base = f"incident-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"
    if vault is None:
        return base
    label, n = base, 2
    while vault.has(label):
        label = f"{base}-{n}"
        n += 1
    return label


class Responder(ABC):
    """Template for the five-move ransomware response.

    Subclasses (sqlite engine, mysql engine, AWS control plane) provide the
    four engine-specific moves; the sequencing, evidence sealing, clock
    marking and the refusal-to-guess rule are fixed here so every engine
    responds the same way.
    """

    def __init__(self, vault, clock: ProofClock | None = None):
        self.vault = vault
        self.clock = clock or ProofClock()

    # ------------------------------------------------------------------
    # engine-specific moves (abstract)
    # ------------------------------------------------------------------
    @abstractmethod
    def isolate(self) -> None:
        """Cut the attacker off from the primary."""

    @abstractmethod
    def isolation_proofs(self) -> list:
        """Proofs that the attacker is really locked out."""

    @abstractmethod
    def restore_replica(self, clean: dict, clean_bytes: bytes) -> None:
        """Bring up the break-glass read-only replica from a clean seal."""

    @abstractmethod
    def replica_proofs(self) -> list:
        """Proofs that the replica is verified and read-only."""

    # ------------------------------------------------------------------
    # shared template
    # ------------------------------------------------------------------
    def on_tamper(self, signal) -> ResponseReport:
        """Run the full playbook. Returns a ResponseReport."""
        self.clock.detect()
        proofs: list = []

        payload = json.dumps({
            "source": getattr(signal, "source", "unknown"),
            "canary_id": getattr(signal, "canary_id", None),
            "expected": getattr(signal, "expected", None),
            "observed": getattr(signal, "observed", None),
            "detail": getattr(signal, "detail", ""),
        }, sort_keys=True).encode()
        self.vault.seal(incident_label(self.vault), payload,
                        meta={"kind": "incident"})

        self.isolate()
        proofs += self.isolation_proofs()
        self.clock.isolation_verified()

        clean = self._clean_record()
        clean_bytes = self.vault.read(clean["label"])
        self.restore_replica(clean, clean_bytes)
        proofs += self.replica_proofs()
        self.clock.replica_serving()

        return ResponseReport(proofs=proofs, clock=self.clock)

    def _clean_record(self) -> dict:
        """The one snapshot we are willing to restore from."""
        for entry in self.vault.entries():
            if entry["label"] == "baseline":
                return entry
        raise RuntimeError(
            "no 'baseline' seal in the vault - refusing to guess which "
            "snapshot is clean; seal a baseline before the drill runs"
        )
