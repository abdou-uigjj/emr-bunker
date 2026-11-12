"""Fake AWS clients for the lambda/aws responder contract tests.

They mimic exactly the API surface the AWSResponder touches and record
every call in order, so tests can assert the playbook's call sequence
and the tags it stamps on incident evidence.
"""

from __future__ import annotations

import json


class FakeWaiter:
    def __init__(self, log):
        self.log = log

    def wait(self, **kwargs):
        self.log.append(("waiter:db_instance_available", kwargs.get(
            "DBInstanceIdentifier")))


class FakeRDS:
    def __init__(self):
        self.log = []
        self.instances = {
            "emr-primary": {
                "DBInstanceIdentifier": "emr-primary",
                "VpcSecurityGroups": [
                    {"VpcSecurityGroupId": "sg-app-1"},
                ],
                "DBParameterGroups": [
                    {"DBParameterGroupName": "default.mysql8"},
                ],
                "PubliclyAccessible": True,
            },
        }
        self.snapshots = []

    def create_db_snapshot(self, **kwargs):
        self.log.append(("create_db_snapshot", kwargs))
        self.snapshots.append(kwargs)

    def modify_db_instance(self, **kwargs):
        self.log.append(("modify_db_instance", kwargs))
        inst = self.instances[kwargs["DBInstanceIdentifier"]]
        if "VpcSecurityGroupIds" in kwargs:
            inst["VpcSecurityGroups"] = [
                {"VpcSecurityGroupId": s}
                for s in kwargs["VpcSecurityGroupIds"]
            ]

    def describe_db_instances(self, **kwargs):
        self.log.append(("describe_db_instances", kwargs))
        inst = self.instances[kwargs["DBInstanceIdentifier"]]
        return {"DBInstances": [inst]}

    def restore_db_instance_from_db_snapshot(self, **kwargs):
        self.log.append(("restore_db_instance_from_db_snapshot", kwargs))
        self.instances[kwargs["DBInstanceIdentifier"]] = {
            "DBInstanceIdentifier": kwargs["DBInstanceIdentifier"],
            "VpcSecurityGroups": [
                {"VpcSecurityGroupId": s}
                for s in kwargs["VpcSecurityGroupIds"]
            ],
            "DBParameterGroups": [
                {"DBParameterGroupName":
                 kwargs["DBParameterGroupName"]},
            ],
            "PubliclyAccessible": kwargs["PubliclyAccessible"],
        }

    def get_waiter(self, name):
        self.log.append(("get_waiter", name))
        return FakeWaiter(self.log)


class FakeEC2:
    def __init__(self):
        self.log = []

    def modify_db_instance(self, **kwargs):
        # real call goes through rds; kept for symmetry
        self.log.append(("modify_db_instance", kwargs))


class FakeSNS:
    def __init__(self):
        self.log = []

    def publish(self, **kwargs):
        self.log.append(("publish", kwargs))
