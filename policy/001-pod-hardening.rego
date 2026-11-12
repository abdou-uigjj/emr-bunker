package main

# 001 - pod hardening: nothing in the clinic namespace runs privileged,
# as root, or with a writable root filesystem.

deny[msg] {
  input.kind == "Pod"
  c := input.spec.containers[_]
  c.securityContext.privileged == true
  msg := sprintf("container %s is privileged", [c.name])
}

deny[msg] {
  input.kind == "Pod"
  c := input.spec.containers[_]
  not c.securityContext.runAsNonRoot == true
  msg := sprintf("container %s must set runAsNonRoot: true", [c.name])
}

deny[msg] {
  input.kind == "Pod"
  c := input.spec.containers[_]
  not c.securityContext.seccompProfile.type == "RuntimeDefault"
  msg := sprintf("container %s must pin seccompProfile RuntimeDefault", [c.name])
}

deny[msg] {
  input.kind == "Pod"
  c := input.spec.containers[_]
  not c.securityContext.readOnlyRootFilesystem == true
  msg := sprintf("container %s must set readOnlyRootFilesystem: true", [c.name])
}

deny[msg] {
  input.kind == "Pod"
  c := input.spec.containers[_]
  not c.securityContext.capabilities.drop
  msg := sprintf("container %s must drop ALL capabilities", [c.name])
}

deny[msg] {
  input.kind == "Pod"
  c := input.spec.containers[_]
  d := c.securityContext.capabilities.drop
  not drops_all(d)
  msg := sprintf("container %s must drop ALL capabilities", [c.name])
}

drops_all(d) {
  d[_] == "ALL"
}
