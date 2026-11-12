import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from canary.agent import CanaryAgent  # noqa: E402
from canary.stores import FileCanaryStore, MultiStore, write_honeypots  # noqa: E402
from playbook.core import Proof  # noqa: E402
from playbook.drivers.aws import AWSResponder  # noqa: E402
from playbook.timing import RESPONSE_BUDGET_SECONDS, ProofClock  # noqa: E402
from tests.fake_responder import FakeRDS, FakeSNS  # noqa: E402


# ----------------------------------------------------------------------
# clock
# ----------------------------------------------------------------------
def test_marks_are_first_wins():
    clock = ProofClock()
    first = clock.detect()
    clock.detect()
    assert clock.get("t0_detect") == first
    clock.isolation_verified()
    clock.replica_serving()
    rep = clock.report()
    assert rep.complete and rep.within_budget


def test_over_budget_fails():
    clock = ProofClock(budget_seconds=0.0)
    clock.detect()
    time.sleep(0.01)
    clock.isolation_verified()
    time.sleep(0.01)
    clock.replica_serving()
    rep = clock.report()
    assert rep.complete
    assert not rep.within_budget


def test_default_budget_is_60s():
    assert RESPONSE_BUDGET_SECONDS == 60.0


# ----------------------------------------------------------------------
# canary behaviours
# ----------------------------------------------------------------------
def test_canary_ignores_new_files(tmp_path):
    d = tmp_path / "docs"
    write_honeypots(str(d), count=3)
    store = FileCanaryStore(str(d))
    agent = CanaryAgent(store)
    agent.arm()
    (d / "new-upload.pdf").write_bytes(b"brand new")
    assert agent.check_once() == []


def test_unarmed_canary_refuses(tmp_path):
    d = tmp_path / "docs"
    write_honeypots(str(d), count=2)
    agent = CanaryAgent(FileCanaryStore(str(d)))
    with pytest.raises(RuntimeError, match="not armed"):
        agent.check_once()


def test_multi_store_aggregates(tmp_path):
    d = tmp_path / "docs"
    write_honeypots(str(d), count=2)
    store = FileCanaryStore(str(d))
    multi = MultiStore([store])
    ids = [cid for cid, _ in multi.decoys()]
    assert ids == [f"file:{p}" for p in
                   sorted(p.name for p in d.glob("*.pdf"))]
    assert multi.observe(ids[0]) == store.observe(ids[0])


# ----------------------------------------------------------------------
# proof object
# ----------------------------------------------------------------------
def test_proof_serializes():
    p = Proof("x", True, "detail")
    assert p.as_dict() == {"name": "x", "passed": True, "detail": "detail"}


# ----------------------------------------------------------------------
# AWS responder contract (fakes, no boto3)
# ----------------------------------------------------------------------
def test_aws_responder_full_playbook_call_order(tmp_path):
    from playbook.vault import SealedVault

    vault = SealedVault(tmp_path / "vault", key=b"k" * 48)
    descriptor = json.dumps({
        "kind": "rds-snapshot",
        "snapshot_id": "snap-baseline",
        "instance": "emr-primary",
    }).encode()
    vault.seal("baseline", descriptor,
               meta={"kind": "baseline", "snapshot_id": "snap-baseline"})

    rds, sns = FakeRDS(), FakeSNS()
    responder = AWSResponder(
        vault, clock=ProofClock(), rds=rds, sns=sns,
        db_instance_id="emr-primary",
        quarantine_sgs=["sg-quarantine"],
        breakglass_sgs=["sg-breakglass"],
        breakglass_param_group="emr-bunker-breakglass",
        restore_instance_id="emr-breakglass",
        page_topic_arn="arn:topic",
    )

    class Sig:
        source = "guardduty"
        canary_id = "fake"
        expected = "a"
        observed = "b"
        detail = "test"

    report = responder.on_tamper(Sig())

    names = [p.name for p in report.proofs]
    assert names == [
        "quarantine-sg-applied",
        "replica-hash-match",
        "replica-breakglass-param-group",
        "replica-breakglass-sgs",
        "replica-not-public",
    ]
    assert report.ok

    calls = [c[0] for c in rds.log]
    assert calls[0] == "modify_db_instance"
    assert calls[1] == "describe_db_instances"
    assert "restore_db_instance_from_db_snapshot" in calls
    assert calls[-1] == "describe_db_instances"

    restore = next(c for c in rds.log
                   if c[0] == "restore_db_instance_from_db_snapshot")[1]
    assert restore["DBSnapshotIdentifier"] == "snap-baseline"
    assert restore["DBParameterGroupName"] == "emr-bunker-breakglass"
    assert restore["PubliclyAccessible"] is False

    page = sns.log[0][1]
    assert page["TopicArn"] == "arn:topic"
    assert "isolate" in page["Message"]


def test_aws_snapshot_is_tagged_as_incident_seal(tmp_path):
    from playbook.vault import SealedVault

    vault = SealedVault(tmp_path / "vault", key=b"k" * 48)
    rds = FakeRDS()
    responder = AWSResponder(vault, rds=rds, db_instance_id="emr-primary")
    desc = responder.snapshot_bytes()
    snap = rds.snapshots[0]
    assert snap["Tags"] == [
        {"Key": "emr-bunker", "Value": "incident-seal"},
        {"Key": "emr-bunker:kind", "Value": "baseline"},
    ]
    assert json.loads(desc)["snapshot_id"] == snap["DBSnapshotIdentifier"]


def test_aws_replica_proofs_catch_a_lax_restore(tmp_path):
    from playbook.vault import SealedVault

    vault = SealedVault(tmp_path / "vault", key=b"k" * 48)
    rds, sns = FakeRDS(), FakeSNS()
    responder = AWSResponder(
        vault, clock=ProofClock(), rds=rds, sns=sns,
        db_instance_id="emr-primary",
        quarantine_sgs=["sg-quarantine"],
        breakglass_sgs=["sg-breakglass"],
        restore_instance_id="emr-breakglass",
    )
    # restore into a lax config: public + default param group
    rds.instances["emr-breakglass"] = {
        "DBInstanceIdentifier": "emr-breakglass",
        "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-app-1"}],
        "DBParameterGroups": [
            {"DBParameterGroupName": "default.mysql8"}],
        "PubliclyAccessible": True,
    }
    proofs = responder.replica_proofs()
    assert not all(p.passed for p in proofs)
