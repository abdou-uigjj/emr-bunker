import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from canary.agent import CanaryAgent  # noqa: E402
from playbook.drivers.local import LocalResponder  # noqa: E402
from playbook.drivers.sqlite_engine import SqliteEngine  # noqa: E402
from playbook.timing import ProofClock  # noqa: E402
from playbook.vault import SealedVault  # noqa: E402


def build(tmp_path):
    root = tmp_path / "emr"
    engine = SqliteEngine(str(root))
    engine.seed(patients=200, canaries=8)
    vault = SealedVault(tmp_path / "vault", key=b"k" * 48)
    snapshot = engine.snapshot_bytes()
    vault.seal("baseline", snapshot,
               meta={"kind": "baseline",
                     "content_hash": engine.content_hash()})
    agent = CanaryAgent(engine.canary_store(), interval=0.1)
    agent.arm()
    return engine, vault, agent


def test_canary_catches_row_tamper(tmp_path):
    engine, _, agent = build(tmp_path)
    attacker = engine.attacker()
    attacker.encrypt_mass(offset=0, count=50)
    signals = agent.check_once()
    assert signals, "canary slept through a 50-row sweep"
    sig = signals[0]
    assert sig.canary_id.startswith("row:")
    assert "sqlite" in sig.source
    assert sig.expected != sig.observed


def test_canary_catches_document_tamper(tmp_path):
    engine, _, agent = build(tmp_path)
    attacker = engine.attacker()
    attacker.encrypt_documents()
    signals = agent.check_once()
    assert signals
    assert any(s.canary_id.startswith("file:") for s in signals)


def test_full_cycle_holds(tmp_path):
    engine, vault, agent = build(tmp_path)
    attacker = engine.attacker()
    attacker.encrypt_mass(offset=0, count=50)
    signal = agent.check_once()[0]
    report = LocalResponder(engine, vault, clock=ProofClock()).on_tamper(
        signal)
    names = [p.name for p in report.proofs]
    assert names == [
        "attacker-write-denied",
        "primary-locked",
        "replica-hash-match",
        "replica-read-only",
    ]
    assert all(p.passed for p in report.proofs), \
        [p.as_dict() for p in report.proofs if not p.passed]
    assert report.within_budget
    assert report.ok
    # incident evidence + baseline + runbook live in the vault
    labels = [e["label"] for e in vault.entries()]
    assert any(l.startswith("incident-") for l in labels)
    assert "baseline" in labels


def test_no_baseline_refuses_to_guess(tmp_path):
    engine = SqliteEngine(str(tmp_path / "emr2"))
    engine.seed(patients=50, canaries=4)
    vault = SealedVault(tmp_path / "vault2", key=b"k" * 48)
    vault.seal("response-runbook", b"plan", meta={"kind": "runbook"})
    agent = CanaryAgent(engine.canary_store(), interval=0.1)
    agent.arm()
    attacker = engine.attacker()
    attacker.encrypt_mass(offset=0, count=50)
    signal = agent.check_once()[0]
    with pytest.raises(RuntimeError, match="refusing to guess"):
        LocalResponder(engine, vault, clock=ProofClock()).on_tamper(signal)


def test_second_incident_gets_its_own_seal(tmp_path):
    engine, vault, agent = build(tmp_path)
    attacker = engine.attacker()
    attacker.encrypt_mass(offset=0, count=50)
    first = LocalResponder(engine, vault, clock=ProofClock()).on_tamper(
        agent.check_once()[0])
    assert first.ok

    # rebuild the clinic; the vault (with its baseline) survives
    engine.wipe()
    engine.seed(patients=200, canaries=8)
    agent2 = CanaryAgent(engine.canary_store(), interval=0.1)
    agent2.arm()
    attacker = engine.attacker()
    attacker.encrypt_mass(offset=50, count=50)
    second = LocalResponder(engine, vault, clock=ProofClock()).on_tamper(
        agent2.check_once()[0])
    assert second.ok
    incidents = [e["label"] for e in vault.entries()
                 if e["label"].startswith("incident-")]
    assert len(incidents) == 2
    assert len(set(incidents)) == 2
