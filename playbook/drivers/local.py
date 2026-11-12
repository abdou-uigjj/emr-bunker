"""Engine abstraction - nine primitives, any backend.

An Engine knows how to:

    seed()               build a believable little EMR (patients + canaries)
    content_hash()       fingerprint the primary right now
    canary_store()       the tripwire store the CanaryAgent polls
    attacker()           a scripted adversary the drill lets loose
    snapshot_bytes()     a full, restorable image of the primary (seal time)
    isolate()            cut the attacker off
    isolation_proofs()   prove the lockout
    restore_replica()    rebuild a read-only replica from clean bytes
    replica_proofs()     prove the replica is verified + read-only

The sqlite engine runs on a laptop; the mysql engine drives a real
primary/replica pair; the AWS engine maps the same moves onto the
RDS/Backup control plane. The drill never knows which one it is talking to.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..core import Responder


class Engine(ABC):
    """The nine primitives every emr-bunker backend implements."""

    @abstractmethod
    def seed(self, patients: int = 200, canaries: int = 8) -> None:
        """Create the fake patient records and the canary decoys."""

    @abstractmethod
    def content_hash(self) -> str:
        """Fingerprint of the primary as it stands right now."""

    @abstractmethod
    def canary_store(self):
        """CanaryStore for the CanaryAgent to poll."""

    @abstractmethod
    def attacker(self):
        """A fresh scripted adversary."""

    @abstractmethod
    def snapshot_bytes(self) -> bytes:
        """Full image of the primary, restorable into a replica."""

    @abstractmethod
    def isolate(self) -> None:
        """Cut the attacker off from the primary."""

    @abstractmethod
    def isolation_proofs(self) -> list:
        """Proof objects showing the attacker is locked out."""

    @abstractmethod
    def restore_replica(self, clean: dict, clean_bytes: bytes) -> None:
        """Restore `clean_bytes` into the break-glass replica."""

    @abstractmethod
    def replica_proofs(self) -> list:
        """Proof objects showing the replica is verified and read-only."""


class LocalResponder(Responder):
    """Responder that delegates the four moves to a local Engine."""

    def __init__(self, engine: Engine, vault, clock=None):
        super().__init__(vault, clock=clock)
        self.engine = engine

    def isolate(self) -> None:
        self.engine.isolate()

    def isolation_proofs(self) -> list:
        return self.engine.isolation_proofs()

    def restore_replica(self, clean: dict, clean_bytes: bytes) -> None:
        self.engine.restore_replica(clean, clean_bytes)

    def replica_proofs(self) -> list:
        return self.engine.replica_proofs()
