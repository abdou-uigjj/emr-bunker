"""emr-bunker Lambda - the response control plane.

Trigger sources wired in terraform:

  * GuardDuty finding (EventBridge rule, severity >= threshold)
  * canary webhook    (the CanaryAgent sidecar POSTs its signal)

Both normalize into the same five-move playbook that every engine uses.
Low-severity noise is ignored; anything real runs the proven Responder
template and returns the full proof + clock report for the audit trail.
"""

from __future__ import annotations

import base64
import json
import os

from playbook.core import Responder
from playbook.timing import ProofClock
from playbook.vault import SealedVault

MIN_SEVERITY = 7


def extract_finding(event: dict) -> dict | None:
    """Normalize GuardDuty findings and canary webhooks.

    Returns {'source','severity','title','signal'} or None when the
    event is neither.
    """
    if not isinstance(event, dict):
        return None

    detail = event.get("detail")
    if isinstance(detail, dict) and detail.get("type") \
            and "severity" in detail:
        severity = int(detail.get("severity") or 0)
        return {
            "source": "guardduty",
            "severity": severity,
            "title": detail["type"],
            "signal": _signal(
                source="guardduty",
                canary_id=str(detail.get("resource", {}).get(
                    "resourceType", "guardduty-finding")),
                detail=str(detail.get("title", detail["type"])),
            ),
        }

    body = event.get("body")
    if isinstance(body, str):
        try:
            body = json.loads(body)
        except (ValueError, TypeError):
            return None
    if isinstance(body, list) and body:
        first = body[0]
        if isinstance(first, dict) and first.get("source"):
            return {
                "source": "canary",
                "severity": 10,
                "title": f"canary tamper: {first.get('canary_id')}",
                "signal": _signal(
                    source="canary",
                    canary_id=str(first.get("canary_id", "unknown")),
                    expected=str(first.get("expected", "")),
                    observed=str(first.get("observed", "")),
                    detail=str(first.get("detail", "")),
                ),
            }
    return None


def _signal(**kwargs):
    from canary.agent import TamperSignal

    return TamperSignal(
        source=kwargs.get("source", "unknown"),
        canary_id=kwargs.get("canary_id", "unknown"),
        expected=kwargs.get("expected", ""),
        observed=kwargs.get("observed", ""),
        detail=kwargs.get("detail", ""),
    )


def build_responder(vault: SealedVault, clock: ProofClock | None = None):
    """Seam for tests: the real deployment uses the AWS control plane."""
    from playbook.drivers.aws import AWSResponder

    return AWSResponder.from_env(vault, clock=clock)


def handler(event, context=None) -> dict:
    finding = extract_finding(event)
    if finding is None:
        return {"action": "ignored", "reason": "event is not a finding"}

    if finding["severity"] < MIN_SEVERITY:
        return {
            "action": "ignored",
            "reason": f"severity {finding['severity']} below "
                      f"threshold {MIN_SEVERITY}",
        }

    key = base64.b64decode(os.environ["EMR_BUNKER_VAULT_KEY"])
    vault = SealedVault(os.environ.get("EMR_BUNKER_VAULT_ROOT",
                                       "/tmp/emr-bunker-vault"), key)
    responder = build_responder(vault)
    if not isinstance(responder, Responder):
        raise TypeError("build_responder must return a playbook Responder")

    report = responder.on_tamper(finding["signal"])
    return {
        "action": "responded",
        "ok": report.ok,
        "finding": {"source": finding["source"],
                    "title": finding["title"],
                    "severity": finding["severity"]},
        "proofs": report.as_dict()["proofs"],
        "clock": report.as_dict()["clock"],
    }
