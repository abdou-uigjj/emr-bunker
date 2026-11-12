# the provable gate

Most security repos make claims. This one makes a test that can fail.

## what the drill does

`python3 drill/ransomware_drill.py` runs, for real:

1. **builds a clinic** - 200 patient charts in sqlite, 8 decoy rows
   distributed through the id space, 4 honeypot referral PDFs in the
   documents folder
2. **seals the baseline** - a full snapshot of the clinic goes into the
   SealedVault with the content fingerprint in its meta; the response
   runbook is sealed too, so the incident record contains the plan
3. **arms the canary** - the agent snapshots digests of all 12 decoys
4. **releases the attacker** - it encrypts patient rows in 50-row
   windows, sweeping by offset exactly the way mass-encryption
   payloads do
5. **catches the tamper** - the canary compares current digests to the
   armed digests and fires the moment a decoy changes
6. **runs the playbook** - incident seal, isolate, prove severance,
   restore, prove serving - the full template from `playbook/core.py`
7. **prints the verdict** - one line per proof, the clock, and
   `PROOF HOLDS` or `PROOF FAILED`

The exit code is nonzero unless every proof passed and the whole
response fit inside the 60-second budget. CI runs the drill as its own
job; a green pipeline is a fresh proof, not a stale document.

## what each proof means

| proof | how it is checked |
|---|---|
| attacker-write-denied | the engine actually attempts a write as the attacker and requires the refusal |
| primary-locked | the file modes on the primary really deny write bits |
| replica-hash-match | the restored replica's content fingerprint equals the fingerprint sealed in the baseline meta |
| replica-read-only | a write through the read-only URI is refused and the replica files carry no write bits |

For the aws engine the equivalent proofs are checked against the real
API state: quarantine SGs attached, break-glass parameter group active,
`PubliclyAccessible=false`, and the restored instance pinned to the
snapshot id that the vault sealed.

## why the clock matters

The T0 -> T1 -> T2 marks make the response *measurable*: detection
time, isolation time, serving time. First-mark-wins means the report
cannot be flattered after the fact. The budget (60 seconds default)
is asserted, not aspirational - a run that overruns fails the drill
even if every proof passed.

## why the negative tests matter

`make policy-negative` feeds deliberately bad manifests (privileged
pods, NodePort doors, canary-less deployments, `:latest` images) to
the conftest pack and **requires** them to be rejected. A policy pack
that passes everything is decoration. The drill has its own negative:
if the attacker finishes the table and the canary never fired, the
drill reports the tripwire as broken and exits nonzero.

## what a red drill means

If the drill goes red in CI, one of these is true:

- a code change broke a proof (the gate did its job)
- an engine refactor changed the response contract (update proofs
  deliberately, never silently)
- the environment cannot enforce the control (running as root makes
  file lockout meaningless - the engine reports that honestly as a
  failed proof rather than a fake pass)

All three deserve a human looking. That is the point.
