EMR-BUNKER CHANGELOG
====================

v1.0.0 - 2026-11-12
-------------------
first release.

* canary tripwire: decoy patient rows + honeypot documents, polled by
  a sidecar agent (CanaryAgent) and a shared store layer
* SealedVault: write-once, HMAC-chained evidence store; tamper,
  reorder, drop and wrong-key all fail closed
* response playbook (Responder template): incident seal -> isolate ->
  prove severance -> restore last-clean baseline into a break-glass
  read-only replica -> prove serving, with the refusal-to-guess rule
* three engines behind one nine-primitive abstraction: sqlite
  (clinic-in-a-box), mysql (real primary/bunker pair for CI), aws
  (RDS snapshot + quarantine SG swap + break-glass restore, Lambda
  control plane)
* ProofClock: T0 detect -> T1 isolated -> T2 replica serving, 60
  second response budget, first-mark-wins
* ransomware drill: real attacker sweeps, canary fires mid-run, full
  playbook, verdict table, nonzero exit unless every proof holds
* terraform: private-only VPC, RDS encrypted/deletion-protected/
  multi-AZ, Backup Vault Lock compliance mode (90 day minimum),
  GuardDuty + EventBridge severity gate, zero-rule quarantine SG,
  break-glass parameter group, private EKS
* conftest policy pack with negative fixtures (bad manifests must
  fail CI)
* k8s: restricted PodSecurity namespace, default-deny netpols, single
  path netpol, OpenEMR deployment with the canary sidecar welded on
* CI: yamllint + shellcheck + pytest + conftest(good)+conftest(bad)
  + terraform gates + the drill itself
