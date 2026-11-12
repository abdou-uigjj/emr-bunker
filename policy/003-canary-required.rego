package main

# 003 - the canary is mandatory: every OpenEMR pod ships the canary
# sidecar (the tripwire the ransomware drill arms). A pod without it is
# unmonitored, and unmonitored is how ransomware gets a week head start.

deny[msg] {
  input.kind == "Deployment"
  input.metadata.labels.app == "openemr"
  containers := input.spec.template.spec.containers
  not canary_present(containers)
  msg := sprintf("openemr deployment %s is missing the canary sidecar", [input.metadata.name])
}

canary_present(containers) {
  c := containers[_]
  c.name == "canary"
}
