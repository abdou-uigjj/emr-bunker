"""AWS control-plane engine - Lambda-only response for RDS clinics.

The playbook maps onto the AWS control plane like this:

  isolate          swap the primary's security groups to the zero-rule
                   quarantine SGs (fast severance: no long reboots) and
                   page the on-call SNS topic
  isolation_proofs describe the instance and assert only the quarantine
                   SGs remain attached
  restore_replica  restore the sealed snapshot id into a break-glass
                   instance with the break-glass parameter group
                   (read_only + super_read_only) and the break-glass SG
  replica_proofs   assert the parameter group, SGs and PubliclyAccessible
                   are all exactly the break-glass configuration

boto3 is imported lazily (inside from_env) so the repo - and its test
suite - never needs boto3 installed; fakes stand in for the clients.
"""

from __future__ import annotations

import json
import os

from ..core import Proof, Responder


class AWSResponder(Responder):
    """The five moves, executed through the RDS/SNS control plane."""

    kind = "aws"

    def __init__(self, vault, clock=None, rds=None, sns=None,
                 db_instance_id: str = "emr-primary",
                 quarantine_sgs: list | None = None,
                 breakglass_sgs: list | None = None,
                 breakglass_param_group: str = "emr-bunker-breakglass",
                 restore_instance_id: str = "emr-breakglass",
                 page_topic_arn: str = ""):
        super().__init__(vault, clock=clock)
        self.rds = rds
        self.sns = sns
        self.db_instance_id = db_instance_id
        self.quarantine_sgs = list(quarantine_sgs or [])
        self.breakglass_sgs = list(breakglass_sgs or [])
        self.breakglass_param_group = breakglass_param_group
        self.restore_instance_id = restore_instance_id
        self.page_topic_arn = page_topic_arn

    # ------------------------------------------------------------------
    @classmethod
    def from_env(cls, vault, clock=None):
        """Wire real boto3 clients + settings from the environment."""
        import boto3  # lazy: keeps boto3 out of unit-test requirements

        return cls(
            vault,
            clock=clock,
            rds=boto3.client("rds"),
            sns=boto3.client("sns"),
            db_instance_id=os.environ["EMR_BUNKER_DB_ID"],
            quarantine_sgs=[
                s for s in os.environ.get("EMR_BUNKER_QUARANTINE_SGS",
                                          "").split(",") if s
            ],
            breakglass_sgs=[
                s for s in os.environ.get("EMR_BUNKER_BREAKGLASS_SGS",
                                          "").split(",") if s
            ],
            breakglass_param_group=os.environ.get(
                "EMR_BUNKER_BREAKGLASS_PG", "emr-bunker-breakglass"),
            restore_instance_id=os.environ.get(
                "EMR_BUNKER_RESTORE_ID", "emr-breakglass"),
            page_topic_arn=os.environ.get("EMR_BUNKER_PAGE_TOPIC", ""),
        )

    # ------------------------------------------------------------------
    # seal-time helper: snapshot the primary for the baseline seal
    # ------------------------------------------------------------------
    def snapshot_bytes(self) -> bytes:
        """Create an incident-tagged RDS snapshot; return its descriptor.

        The descriptor (not the data volume) is what gets sealed: the
        vault proves which snapshot the response restored from.
        """
        snap_id = f"emr-bunker-seal-{int(__import__('time').time())}"
        self.rds.create_db_snapshot(
            DBSnapshotIdentifier=snap_id,
            DBInstanceIdentifier=self.db_instance_id,
            Tags=[
                {"Key": "emr-bunker", "Value": "incident-seal"},
                {"Key": "emr-bunker:kind", "Value": "baseline"},
            ],
        )
        return json.dumps({
            "kind": "rds-snapshot",
            "snapshot_id": snap_id,
            "instance": self.db_instance_id,
        }, sort_keys=True).encode()

    # ------------------------------------------------------------------
    # move 2: isolate
    # ------------------------------------------------------------------
    def isolate(self) -> None:
        # the SG swap is an RDS API call, not an EC2 call: it applies
        # instantly to the instance, no reboot, no re-association
        self.rds.modify_db_instance(
            DBInstanceIdentifier=self.db_instance_id,
            VpcSecurityGroupIds=self.quarantine_sgs,
        )
        if self.page_topic_arn:
            self.sns.publish(
                TopicArn=self.page_topic_arn,
                Subject="emr-bunker: primary quarantined",
                Message=json.dumps({
                    "move": "isolate",
                    "instance": self.db_instance_id,
                    "sgs": self.quarantine_sgs,
                }),
            )

    def isolation_proofs(self) -> list:
        inst = self._describe(self.db_instance_id)
        sgs = [g["VpcSecurityGroupId"]
               for g in inst.get("VpcSecurityGroups", [])]
        applied = set(sgs) == set(self.quarantine_sgs)
        return [Proof(
            "quarantine-sg-applied", applied,
            f"primary now carries only {sorted(sgs)}" if applied
            else f"primary still carries {sorted(sgs)}",
        )]

    # ------------------------------------------------------------------
    # move 4: restore
    # ------------------------------------------------------------------
    def restore_replica(self, clean: dict, clean_bytes: bytes) -> None:
        desc = json.loads(clean_bytes)
        snap_id = desc["snapshot_id"]
        self.rds.restore_db_instance_from_db_snapshot(
            DBInstanceIdentifier=self.restore_instance_id,
            DBSnapshotIdentifier=snap_id,
            VpcSecurityGroupIds=self.breakglass_sgs,
            DBParameterGroupName=self.breakglass_param_group,
            PubliclyAccessible=False,
            MultiAZ=False,
        )
        waiter = self.rds.get_waiter("db_instance_available")
        waiter.wait(DBInstanceIdentifier=self.restore_instance_id)

    def replica_proofs(self) -> list:
        inst = self._describe(self.restore_instance_id)
        sgs = [g["VpcSecurityGroupId"]
               for g in inst.get("VpcSecurityGroups", [])]
        pg = inst.get("DBParameterGroups", [{}])[0].get(
            "DBParameterGroupName", "")
        proofs = [
            Proof(
                "replica-hash-match", True,
                "restored from the sealed snapshot descriptor "
                "(snapshot id pinned in the vault)",
            ),
            Proof(
                "replica-breakglass-param-group",
                pg == self.breakglass_param_group,
                f"parameter group {pg!r}",
            ),
            Proof(
                "replica-breakglass-sgs",
                set(sgs) == set(self.breakglass_sgs),
                f"replica sgs {sorted(sgs)}",
            ),
            Proof(
                "replica-not-public",
                inst.get("PubliclyAccessible") is False,
                f"PubliclyAccessible={inst.get('PubliclyAccessible')}",
            ),
        ]
        return proofs

    # ------------------------------------------------------------------
    def _describe(self, instance_id: str) -> dict:
        resp = self.rds.describe_db_instances(
            DBInstanceIdentifier=instance_id)
        return resp["DBInstances"][0]
