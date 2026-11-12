import base64
import importlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

handler = importlib.import_module("lambda.response.handler")
from playbook.core import Responder  # noqa: E402


class FakeResponder(Responder):
    """Standing in for the AWS control plane."""

    def __init__(self, vault, clock=None):
        super().__init__(vault, clock=clock)
        self.tamper_seen = None

    def isolate(self):
        pass

    def isolation_proofs(self):
        from playbook.core import Proof

        return [Proof("fake-isolation", True, "fake")]

    def restore_replica(self, clean, clean_bytes):
        pass

    def replica_proofs(self):
        from playbook.core import Proof

        return [Proof("fake-replica", True, "fake")]


@pytest.fixture
def wired(tmp_path, monkeypatch):
    vault_root = tmp_path / "vault"
    key = base64.b64encode(b"k" * 48).decode()
    monkeypatch.setenv("EMR_BUNKER_VAULT_KEY", key)
    monkeypatch.setenv("EMR_BUNKER_VAULT_ROOT", str(vault_root))
    # the deployment vault always carries a sealed baseline
    from playbook.vault import SealedVault

    SealedVault(vault_root, key=b"k" * 48).seal(
        "baseline", b"descriptor", meta={"kind": "baseline"})
    monkeypatch.setattr(handler, "build_responder",
                        lambda vault, clock=None: FakeResponder(
                            vault, clock=clock))
    return vault_root


def guardduty_event(severity):
    return {
        "source": "aws.guardduty",
        "detail": {
            "type": "UnauthorizedAccess:EC2/Ransomware",
            "severity": severity,
            "title": "Ransomware-like encryption pattern",
            "resource": {"resourceType": "Instance"},
        },
    }


def canary_event():
    return {
        "body": json.dumps([{
            "source": "sqlite-patients",
            "canary_id": "row:37",
            "expected": "aa",
            "observed": "bb",
            "detail": "decoy digest changed",
        }])
    }


def test_guardduty_finding_triggers_response(wired):
    out = handler.handler(guardduty_event(9))
    assert out["action"] == "responded"
    assert out["ok"] is True
    assert out["finding"]["source"] == "guardduty"


def test_low_severity_ignored(wired):
    out = handler.handler(guardduty_event(3))
    assert out["action"] == "ignored"
    assert "below" in out["reason"]


def test_canary_webhook_triggers_response(wired):
    out = handler.handler(canary_event())
    assert out["action"] == "responded"
    assert out["ok"] is True


def test_unrelated_event_ignored(wired):
    out = handler.handler({"foo": "bar"})
    assert out["action"] == "ignored"


def test_lambda_uses_the_proven_core():
    """The lambda must respond through the same playbook template."""
    assert issubclass(FakeResponder, Responder)
    # and the real deployment path stays a Responder too
    from playbook.drivers.aws import AWSResponder

    assert issubclass(AWSResponder, Responder)
