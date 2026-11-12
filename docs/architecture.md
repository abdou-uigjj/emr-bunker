# architecture

emr-bunker is five layers that each exist because of a specific failure
mode observed in real clinic ransomware incidents.

```
                 +-----------------------------------------+
                 |              the clinic                 |
                 |                                         |
                 |  openemr pod          canary sidecar    |
                 |  (charts via rds)     (decoy polling)   |
                 |        |                     |         |
                 |        |            drift = signal     |
                 |        v                     v         |
                 |  +---------+          +------------+    |
                 |  |   rds   | <------- |  response  |    |
                 |  | primary |  SG swap |   lambda   |    |
                 |  +---------+          +-----+------+    |
                 |        |                    |           |
                 |   backup vault lock     sealed evidence |
                 |   (nobody can delete)   vault (chain)   |
                 +-----------------------------------------+
                               break-glass replica
                        (restored snapshot, read-only)
```

## 1. the canary layer (`canary/`)

Decoys are ordinary rows and files. A patient named like any other
patient, a referral PDF like any other PDF. The only marker is an
`is_decoy` column value and a filename pattern - nothing an attacker
can spot without the schema, and nothing they would avoid anyway,
because mass encryption does not discriminate.

`CanaryAgent` polls digests of the decoys. Digest drift is the signal.
There is no scoring, no threshold, no waiting for correlation: one
changed hash is one changed hash.

The sidecar runs beside OpenEMR in the same pod (policy-enforced), and
the drill arms the same store classes directly. Stores exist for
sqlite, mysql and files; `MultiStore` fans one check across all of
them.

## 2. the sealed vault (`playbook/vault.py`)

Incident evidence must survive the attacker having admin. SealedVault
appends entries as `entry_hmac = HMAC(key, prev || label || sha256 ||
size || meta)` - a hash chain over write-once blobs:

- seal a label twice: refused
- edit a blob: the sha256 mismatch fails verify
- reorder or drop entries: the chain breaks at the splice point
- use a different key: every entry_hmac mismatches

Everything fails closed with a reason. The vault is deliberately
boring technology (json + hmac + files) because it must be explainable
to an auditor and reconstructable from a disk image.

## 3. the response playbook (`playbook/core.py`)

One template, five moves:

1. **incident seal** - the trigger evidence (source, canary id,
   expected vs observed digest) goes into the vault before anything
   else happens. If the response itself crashes, the evidence is
   already sealed.
2. **isolate** - the engine cuts the attacker off. Speed is the whole
   game: a security group swap, a `chmod`, a `DROP USER`.
3. **prove severance** - proofs, not assumptions. The sqlite engine
   tries a real write and expects refusal; the aws engine describes the
   instance and expects only the quarantine SGs.
4. **restore** - the last-clean `baseline` seal is fetched from the
   vault and rebuilt into a break-glass replica. If the vault holds no
   baseline, the responder **refuses to guess** and stops: restoring
   an unverifiable snapshot is how clinics restore the ransomware too.
5. **prove serving** - the replica is hash-verified against the meta
   sealed with the baseline and confirmed read-only.

`ProofClock` marks T0/T1/T2 first-wins; `ResponseReport.ok` is true
only when every proof passed and the whole run fits the 60-second
budget.

## 4. the engines (`playbook/drivers/`)

Nine primitives (`Engine` in `drivers/local.py`) separate *what a
response means* from *how a backend does it*:

| primitive | sqlite | mysql | aws |
|---|---|---|---|
| seed | build clinic db | build clinic db | (rds already runs) |
| content_hash | row+file sha256 | row sha256 | snapshot descriptor |
| canary_store | sqlite+files | mysql rows | (lambda webhook) |
| attacker | row sweeps | row sweeps as app user | (guardduty) |
| snapshot_bytes | iterdump+docs zip | mysqldump | create_db_snapshot |
| isolate | chmod lockout | kill sessions, drop user, super_read_only | quarantine SG swap |
| isolation_proofs | real write attempt | real login attempt | describe instance |
| restore_replica | rebuild from dump | replay dump to bunker | restore snapshot |
| replica_proofs | ro-uri write refused | super_read_only + write refused | param group + SGs + not public |

The Lambda (`lambda/response/handler.py`) runs the same `Responder`
template through `AWSResponder` - the control plane responds with the
exact code the laptop drill proved.

## 5. the drill (`drill/ransomware_drill.py`)

The gate that makes the claim falsifiable. See
[provable-gate.md](provable-gate.md).

## 6. the terraform half (`terraform/`)

The prevention-and-ceiling layer: private-only VPC, encrypted
deletion-protected RDS, **Backup Vault Lock compliance mode** (the
90-day wall nobody can tear down), GuardDuty + EventBridge feeding the
Lambda, the pre-built zero-rule quarantine SG, the break-glass
parameter group, private EKS with restricted PodSecurity and the
canary sidecar enforced by conftest policy.
