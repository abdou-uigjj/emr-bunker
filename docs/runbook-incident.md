# incident runbook - the human half

The automation buys you 60 seconds. This runbook is what the human
does next. Read it once now; at 3am you want muscle memory, not
reading.

## you just got paged

The SNS page means the Lambda ran the playbook: the primary is in the
zero-rule quarantine group, and either the break-glass replica is up
or the restore failed. Everything the automation did is in the vault.

## first 10 minutes

1. **Do not unquarantine anything.** The temptation to "just look" at
   the primary is how incidents restart. The quarantine SG has zero
   rules on purpose.
2. **Verify the vault chain:**

   ```bash
   python3 - <<'PY'
   from playbook.vault import SealedVault
   v = SealedVault("/path/to/vault", key=open("vault.key","rb").read())
   print(v.verify())
   PY
   ```

   `ok=True` means the incident record is intact and the timeline is
   trustworthy. `False` means tampering reached the vault itself -
   preserve the directory, do not write to it again, escalate.
3. **Confirm the replica proofs.** The Lambda's return value (CloudWatch
   logs for `/aws/lambda/emr-bunker-response-*`) holds the proof list.
   If `replica-hash-match` is false, the restored copy does not equal
   the sealed baseline - treat the replica as untrusted.

## first hour

4. **Start reading on the replica, not the primary.** The replica is
   read-only by construction. Chart review, patient care continuity:
   all of it happens there.
5. **Decide the rebuild path for the primary.** Two clean options:
   - restore from the Backup Vault (compliance-mode locked - the
     copies are guaranteed intact)
   - rebuild the instance fresh and re-point OpenEMR, using the vault
     baseline for the data

   Do not "clean" the compromised primary in place. Nobody has ever
   been sure enough.
6. **Preserve evidence.** The vault directory, the CloudWatch logs, the
   GuardDuty findings, the quarantined instance's EBS volumes
   (snapshot them - they are covered by the retention policy).

## before you sleep

7. **Rotate the vault key** (Secrets Manager) and the OpenEMR database
   credentials.
8. **Seal a new baseline** once the primary is rebuilt:

   ```bash
   python3 - <<'PY'
   from playbook.drivers.aws import AWSResponder
   from playbook.vault import SealedVault
   # ... build vault/responder, then:
   desc = responder.snapshot_bytes()
   vault.seal("baseline", desc, meta={"kind": "baseline",
               "snapshot_id": desc["snapshot_id"]})
   PY
   ```

   The playbook refuses to respond without a `baseline` seal - the
   next incident must find one waiting.
9. **Run the drill** against the rebuilt setup. The green verdict is
   the close-out evidence that the response still works.

## what to write down

The incident report writes itself from the vault - that is why it
exists: labels, timestamps, the chain, the proofs. Add the human
context (who did what, which regulator gets called when) and you are
done.
