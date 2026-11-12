# emr-bunker

[![CI](https://github.com/abdou-uigjj/emr-bunker/actions/workflows/ci.yml/badge.svg)](https://github.com/abdou-uigjj/emr-bunker/actions/workflows/ci.yml)
![License](https://img.shields.io/badge/license-MIT-green)
![Python](https://img.shields.io/badge/python-3.12-blue)
![Terraform](https://img.shields.io/badge/terraform-1.9.x-purple)
![AWS](https://img.shields.io/badge/aws-rds%20%2B%20eks-orange)

A ransomware-proof wrapper for OpenEMR, built for rural clinics that
cannot afford to lose their charts and cannot afford a security team
either.

Rural clinics are the perfect ransomware target and the worst-defended:
small staff, one overworked IT contractor, patient records that must
never stop being available. When the encryption hits, the choice on the
table is paying or losing years of medical history. emr-bunker exists
so that neither choice comes up.

## the shape of the idea

Ransomware works because it is quiet. It encrypts for days before
anyone notices, and by then the backups were encrypted too. emr-bunker
attacks both halves of that sentence:

1. **a canary that cannot be missed** - decoy patient rows and honeypot
   documents live inside the real data. An encryption sweep that
   touches patient rows touches decoys. The moment any decoy's digest
   changes, a signal fires. Not a heuristic, not an ML score: a hash
   that was there yesterday and is not there now.

2. **a response playbook with a clock on it** - the signal runs five
   moves: seal the incident evidence, isolate the primary, *prove* the
   attacker is locked out, restore the last-clean baseline into a
   break-glass read-only replica, *prove* the replica is verified and
   read-only. The whole run must fit inside a **60-second budget**,
   measured T0 (detect) -> T1 (isolated) -> T2 (replica serving).

3. **evidence that cannot be rewritten** - every step seals into a
   write-once, HMAC-chained vault. Reordering, dropping or editing any
   record breaks the chain. After an incident you have a provable
   account of what happened and when.

## the proof, not the promise

The drill (`python3 drill/ransomware_drill.py`) is not a mock. It
builds a real clinic database (200 charts, 8 decoys, honeypot referral
scans), seals a baseline snapshot, arms the canary, then lets a
scripted adversary sweep the table in 50-row encryption windows. The
canary fires mid-run, the playbook runs, and CI asserts the verdict:

```
  PASS  attacker-write-denied   write to primary db fails
  PASS  primary-locked          db mode 0o440
  PASS  replica-hash-match      replica 041d0ad5d2f1 vs sealed 041d0ad5d2f1
  PASS  replica-read-only       write via ro-uri refused and file modes are locked

  T0 detect 18:39:28 -> T1 isolated 18:39:28 -> T2 replica 18:39:28
  | total 0.003s | budget 60s
  verdict: PROOF HOLDS
```

If the canary never fires, the drill fails. If the lockout leaks, the
drill fails. If the replica diverges from the sealed baseline, the
drill fails. **A repo whose security claim is a test that can go red
is a different species from one whose claim is a paragraph.**

## three engines, one playbook

| engine | where it runs | isolate | restore |
|---|---|---|---|
| sqlite | laptop, clinic-in-a-box, CI | file-mode lockout (0440/0550) | rebuild from sealed dump, read-only URI |
| mysql | real primary + bunker pair (CI job) | kill sessions, drop attacker user, super_read_only | replay sealed mysqldump into bunker, read-only |
| aws | RDS + Lambda control plane | zero-rule quarantine security group swap + SNS page | restore sealed snapshot into break-glass instance with read-only parameter group |

The five moves are one template (`playbook/core.py`); engines supply
nine primitives (`playbook/drivers/local.py`). The drill never knows
which backend it is talking to, and the Lambda runs the *same* proven
template the laptop drill proved.

## the AWS half (terraform/)

- private-only VPC: no internet gateway, no NAT, workloads reachable
  through VPC endpoints only
- RDS: encrypted, multi-AZ, deletion-protected, autoscaling gp3,
  credentials in Secrets Manager
- **Backup Vault Lock in compliance mode, 90-day minimum retention** -
  after the lock cools down, nobody on the planet can delete those
  backups, including whoever owns the account
- GuardDuty (RDS login events, S3 data events, EKS runtime) feeding an
  EventBridge severity gate straight into the response Lambda
- zero-rule quarantine security group pre-built - incident severance is
  a swap, not a scramble
- break-glass parameter group (`read_only`, `super_read_only`,
  `innodb_read_only`) for the restored replica
- private EKS with KMS-encrypted secrets, restricted PodSecurity, and
  the canary sidecar welded onto every OpenEMR pod

## quickstart

```bash
pip install pytest
make test          # 28 unit/contract tests
make drill         # the full attack + response, expect PROOF HOLDS
make policy        # conftest pack over k8s/
make policy-negative   # the bad fixtures must be rejected
make validate      # terraform fmt + validate
```

The mysql engine additionally needs two MySQL 8 servers (primary on
3306, bunker on 3307) and `mysqldump`/`mysql` clients; the CI job
provisions them. The aws engine needs only boto3 and an incident to
hope you never see.

## docs

- [architecture](docs/architecture.md) - every component and why it exists
- [threat model](docs/threat-model.md) - who this is for, who it is against
- [the provable gate](docs/provable-gate.md) - what the drill proves and how
- [incident runbook](docs/runbook-incident.md) - the human half of an incident
- [deployment runbook](docs/runbook-deploy.md) - terraform apply to first drill

## honest limits

emr-bunker is a response-and-evidence machine, not an invulnerability
field. A patient enough attacker who stays below the canary's noise, a
compromised operator workstation, or a clinic that skips the drills
can still get hurt. The 60-second budget is the point: the time
between first touch and last clean snapshot is the entire window a
crew gets. Read [docs/threat-model.md](docs/threat-model.md) before
trusting it with a real clinic.

## license

MIT
