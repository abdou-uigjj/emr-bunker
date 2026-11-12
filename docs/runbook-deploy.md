# deployment runbook

From zero to a drilled, running clinic setup.

## 1. laptop drill (no cloud needed)

```bash
pip install pytest
make test
make drill
```

Expect `PROOF HOLDS`. This proves the playbook end to end on the
sqlite engine in under a minute.

## 2. terraform the AWS half

```bash
cd terraform
# one-time: create the state bucket + dynamodb table by hand, then:
terraform init -backend-config="bucket=<state-bucket>" \
               -backend-config="key=emr-bunker/terraform.tfstate" \
               -backend-config="region=<region>" \
               -backend-config="dynamodb_table=<lock-table>"
cp example.tfvars.example terraform.tfvars   # set clinic_name, oncall_email
terraform plan
terraform apply
```

What this builds: private VPC, encrypted multi-AZ RDS, the Backup
Vault with its 90-day compliance lock, GuardDuty + EventBridge ->
Lambda, the quarantine kit, private EKS, and the break-glass
parameter group.

**The Vault Lock cool-down is 7 days.** After that, retention cannot
be shortened even by root. Plan the first month knowing deletions are
forever.

## 3. seal the first baseline

The response playbook refuses to run without a baseline in the vault:

```bash
make lambda.zip   # packages playbook/ + canary/ + lambda/
```

Deploy the Lambda package, then run a snapshot from a machine with
boto3 + RDS permissions (see `docs/runbook-incident.md` step 8 for
the exact calls) and seal the descriptor as `baseline`. Verify:

```bash
python3 -c "from playbook.vault import SealedVault; \
v=SealedVault('vault', open('vault.key','rb').read()); \
print(v.verify()); print([e['label'] for e in v.entries()])"
```

## 4. the kubernetes half

```bash
aws eks update-kubeconfig --name emr-bunker-<clinic> --region <region>
kubectl apply -f k8s/
```

The namespace enforces restricted PodSecurity, the netpols default-deny
everything except openemr -> bunker-mysql and DNS, and every OpenEMR
pod ships the canary sidecar (policy-enforced - a deployment without
it will not pass CI).

## 5. prove it, then keep proving it

```bash
make policy           # 132 assertions over the manifests
make policy-negative  # the bad fixtures must be rejected
```

And put the drill in a cron slot: a monthly `make drill` red/green is
the difference between a control and a memory.

## the mysql CI variant

The mysql engine drives two real MySQL 8 servers (primary 3306, bunker
3307) for a full round of the same proofs against a real server
pair. The GitHub Actions workflow provisions them; locally you need
`mysqldump`/`mysql` clients and the two servers reachable. Credentials
come from `DRILL_*` environment variables (see
`playbook/drivers/mysql_engine.py`).
