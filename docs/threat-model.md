# threat model

## who this is for

A rural clinic: one OpenEMR instance, one database, a small staff, no
security team, and a regulatory duty to keep years of medical history
available. The budget for security is roughly zero and the tolerance
for downtime is also roughly zero.

## who this is against

The economically rational ransomware crew. They automate: initial
access, privilege escalation, discovery of shares and databases,
exfiltration, then mass encryption - and they sit quietly for days
before the encryption phase. Their toolkit is generic because they
attack hundreds of clinics a month. That genericness is the weakness
emr-bunker attacks: **mass encryption cannot tell a decoy row from a
real one.**

## what is protected

| asset | protection |
|---|---|
| chart data at rest | RDS encryption + private-only VPC |
| chart availability during an incident | 60-second playbook: isolate + restore read-only replica from a sealed clean baseline |
| the backups | Backup Vault Lock compliance mode, 90-day minimum retention, immutable even against account takeover |
| the incident record | HMAC-chained write-once vault; tamper/reorder/drop all fail closed |
| the response decision itself | proofs, not assumptions: every claim the playbook makes is a checkable assertion |

## what is explicitly NOT protected

Being honest here is the difference between a control and a wish:

- **A patient, quiet attacker.** The canary fires on tampering with
  decoys. An attacker who exfiltrates without touching decoy rows or
  honeypot files does not trip it. Exfiltration-only incidents are a
  GuardDuty/DLP problem, not an emr-bunker problem.
- **A compromised operator workstation.** If the admin workstation is
  owned, the crew inherits the runbook's privileges. The vault key
  lives in Secrets Manager; the attacker who owns the account owns the
  timeline. The Vault Lock is what they cannot undo.
- **Sub-canary noise.** An attacker who encrypts real rows but
  magically avoids every decoy row and every honeypot file, without
  ever scanning, is outside the model. This requires knowledge of the
  decoy layout that generic crews do not have - but a targeted crew
  might.
- **Traffic correlation and endpoint compromise of clinicians.** Out
  of scope entirely.
- **The drill budget vs. reality.** The 60-second budget is proven on
  the engine the drill runs. The aws control-plane moves add API
  latency (snapshot + restore are the slow part); the drill budget for
  the aws engine is a deployment decision, documented in the incident
  runbook, not a promise made here.

## the failure model we accept

emr-bunker assumes the perimeter will eventually fail. The design
question is therefore not "how do we keep them out" but "when they are
in, how much of the chart room do they get to keep" - and the answer
is: whatever was written since the last sealed baseline, which is
minutes to hours, not years.

That is the deal: accept a bounded loss, prove the boundary, keep the
evidence chain that shows the boundary held.
