"""CanaryAgent - the watchdog thread.

Arm it, then poll. check_once() re-digests every decoy in the store and
returns one TamperSignal per drifted decoy (empty list = quiet). run()
does that on an interval until stop() is called; _main() is the sidecar
entrypoint for running the agent as its own process (k8s sidecar or
cron), driven by environment variables:

    EMR_BUNKER_STORE      json spec, see _store_from_env
    EMR_BUNKER_INTERVAL   seconds between checks (default 5)
    EMR_BUNKER_SIGNAL     file to write a signal to (default ./signal.json)
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from .stores import (
    CanaryStore, FileCanaryStore, MultiStore, SqliteCanaryStore,
    TamperSignal,
)


class CanaryAgent(threading.Thread):
    """Polls decoy digests; first drift wins."""

    def __init__(self, store: CanaryStore, interval: float = 5.0,
                 signal_sink=None):
        super().__init__(daemon=True, name="canary-agent")
        self.store = store
        self.interval = interval
        self.signal_sink = signal_sink
        self._armed: dict = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()

    # ------------------------------------------------------------------
    def arm(self) -> int:
        """Snapshot every decoy's digest. Returns the decoy count."""
        with self._lock:
            self._armed = dict(self.store.decoys())
            return len(self._armed)

    def check_once(self) -> list:
        """One poll. Returns [TamperSignal, ...] for drifted decoys."""
        if not self._armed:
            raise RuntimeError("canary is not armed - call arm() first")
        signals = []
        for canary_id, expected in list(self._armed.items()):
            observed = self.store.observe(canary_id)
            if observed != expected:
                signals.append(TamperSignal(
                    source=self.store.name,
                    canary_id=canary_id,
                    expected=expected,
                    observed=observed,
                    detail="decoy digest changed",
                ))
        if signals and self.signal_sink:
            self._emit(signals)
        return signals

    def quiet(self) -> bool:
        return not self.check_once()

    # ------------------------------------------------------------------
    def run(self) -> None:
        self.arm()
        while not self._stop.is_set():
            if self.check_once():
                return
            self._stop.wait(self.interval)

    def stop(self) -> None:
        self._stop.set()

    # ------------------------------------------------------------------
    def _emit(self, signals: list) -> None:
        try:
            payload = json.dumps([{
                "source": s.source,
                "canary_id": s.canary_id,
                "expected": s.expected,
                "observed": s.observed,
                "detail": s.detail,
            } for s in signals])
            Path(self.signal_sink).write_text(payload)
        except OSError:
            pass


def _store_from_env(spec: str) -> CanaryStore:
    cfg = json.loads(spec)
    kind = cfg.get("kind")
    if kind == "sqlite":
        return SqliteCanaryStore(cfg["db_path"])
    if kind == "files":
        return FileCanaryStore(cfg["directory"])
    if kind == "multi":
        return MultiStore([_store_from_env(json.dumps(s))
                           for s in cfg["stores"]])
    raise ValueError(f"unknown canary store kind {kind!r}")


def _main() -> int:
    store = _store_from_env(os.environ["EMR_BUNKER_STORE"])
    interval = float(os.environ.get("EMR_BUNKER_INTERVAL", "5"))
    sink = os.environ.get("EMR_BUNKER_SIGNAL", "signal.json")
    agent = CanaryAgent(store, interval=interval, signal_sink=sink)
    agent.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
