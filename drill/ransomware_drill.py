"""The ransomware drill - the provable gate.

One command, one verdict. The drill:

  1. builds a believable clinic EMR (sqlite: 200 charts, 8 decoys,
     honeypot referral scans)
  2. seals the response runbook and a baseline snapshot into a fresh
     SealedVault (baseline carries the content fingerprint in its meta)
  3. arms the canary agent over the decoy rows + honeypot files
  4. lets the scripted attacker sweep the table in 50-row offset windows
  5. the canary fires mid-run -> the full response playbook runs
  6. prints the verdict table and exits nonzero unless every proof
     passed AND the whole response fit inside the budget

The gate is provable because the attack is real: rows really get
encrypted, the canary really fires on a decoy it armed with, the
lockout is really enforced by file modes, and the replica really gets
rebuilt from the sealed baseline and hash-verified.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from canary.agent import CanaryAgent  # noqa: E402
from playbook.drivers.local import LocalResponder  # noqa: E402
from playbook.drivers.sqlite_engine import SqliteEngine  # noqa: E402
from playbook.timing import RESPONSE_BUDGET_SECONDS, ProofClock  # noqa: E402
from playbook.vault import SealedVault, wipe  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ransomware_drill",
        description="emr-bunker ransomware drill: attack the decoys, "
                    "run the response playbook, prove the 60s budget",
    )
    p.add_argument("--engine", choices=["sqlite"], default="sqlite",
                   help="backend engine (mysql/aws variants ship with "
                        "their engines; sqlite needs nothing installed)")
    p.add_argument("--budget", type=float, default=RESPONSE_BUDGET_SECONDS,
                   help="response budget seconds (default 60)")
    p.add_argument("--patients", type=int, default=200)
    p.add_argument("--canaries", type=int, default=8)
    p.add_argument("--sweep", type=int, default=50,
                   help="rows per attacker sweep")
    p.add_argument("--json-out", default=None,
                   help="write the full report as json to this path")
    return p


def run_drill(args) -> int:
    base = Path(tempfile.mkdtemp(prefix="emr-bunker-drill-"))
    engine_root = base / "emr"
    vault_root = base / "vault"

    vault = SealedVault(vault_root, key=__import__("os").urandom(32))
    engine = SqliteEngine(engine_root)

    print(f"== emr-bunker drill | engine={engine.kind} "
          f"| budget={args.budget:.0f}s ==")
    print(f"== workspace: {base} ==")

    # -- build the clinic ------------------------------------------------
    engine.seed(patients=args.patients, canaries=args.canaries)
    print(f"== seeded {args.patients} charts, {args.canaries} decoys, "
          f"honeypot documents in {engine.documents_dir}")

    # -- seal the plan and the baseline ----------------------------------
    runbook = {
        "moves": [
            "seal incident evidence",
            "isolate the primary",
            "prove severance",
            "restore last-clean baseline into break-glass replica",
            "prove replica verified + read-only",
        ],
        "budget_seconds": args.budget,
    }
    vault.seal("response-runbook", json.dumps(runbook, indent=1).encode(),
               meta={"kind": "runbook"})
    snapshot = engine.snapshot_bytes()
    vault.seal("baseline", snapshot,
               meta={"kind": "baseline",
                     "content_hash": engine.content_hash()})
    entries = vault.entries()
    print(f"== vault: sealed {len(entries)} records "
          f"({', '.join(e['label'] for e in entries)})")

    ok_chain, why = vault.verify()
    if not ok_chain:
        print(f"FATAL: vault chain failed before the attack: {why}")
        return 2

    # -- arm the tripwire -------------------------------------------------
    agent = CanaryAgent(engine.canary_store(), interval=0.2)
    armed = agent.arm()
    print(f"== canary armed on {armed} decoys "
          f"({agent.store.name})")

    # -- attack ------------------------------------------------------------
    attacker = engine.attacker()
    signal = None
    total_rows = 0
    t_attack = time.time()
    for offset in range(0, args.patients, args.sweep):
        n = attacker.encrypt_mass(offset=offset, count=args.sweep)
        total_rows += n
        signals = agent.check_once()
        if signals:
            signal = signals[0]
            print(f"== attacker encrypted rows {offset + 1}-{offset + n} "
                  f"({total_rows} total)")
            break
    if signal is None:
        print("FATAL: the attacker finished the table and the canary "
              "never fired - the tripwire is broken")
        return 2
    print(f"== canary fired at {signal.canary_id} "
          f"({time.time() - t_attack:.2f}s into the attack)")

    # -- respond -----------------------------------------------------------
    responder = LocalResponder(engine, vault, clock=ProofClock(
        budget_seconds=args.budget))
    report = responder.on_tamper(signal)

    # -- verdict -----------------------------------------------------------
    clock_rep = report.clock.report()
    print("")
    width = max(len(p.name) for p in report.proofs) + 2
    for p in report.proofs:
        mark = "PASS" if p.passed else "FAIL"
        print(f"  {mark}  {p.name.ljust(width)} {p.detail}")
    t0 = time.strftime("%H:%M:%S", time.localtime(clock_rep.t0_detect)) \
        if clock_rep.t0_detect else "-"
    t1 = time.strftime("%H:%M:%S", time.localtime(clock_rep.t1_isolated)) \
        if clock_rep.t1_isolated else "-"
    t2 = time.strftime("%H:%M:%S", time.localtime(clock_rep.t2_replica_serving)) \
        if clock_rep.t2_replica_serving else "-"
    print("")
    print(f"  T0 detect {t0} -> T1 isolated {t1} -> T2 replica {t2} "
          f"| total {clock_rep.total_seconds}s "
          f"| budget {clock_rep.budget_seconds:.0f}s")
    verdict = "PROOF HOLDS" if report.ok else "PROOF FAILED"
    print(f"  verdict: {verdict}")

    if args.json_out:
        out = {
            "verdict": verdict,
            "signal": {
                "source": signal.source,
                "canary_id": signal.canary_id,
            },
            "rows_encrypted": total_rows,
            "report": report.as_dict(),
        }
        Path(args.json_out).write_text(json.dumps(out, indent=1))

    agent.stop()
    if report.ok:
        print(f"== artifacts kept for inspection: {base}")
        return 0
    print(f"== artifacts kept for inspection: {base}")
    return 1


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return run_drill(args)


if __name__ == "__main__":
    raise SystemExit(main())
