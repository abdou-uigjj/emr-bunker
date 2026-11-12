package main

# 004 - pin images. :latest means every restart is a supply-chain roll
# of the dice on a clinic network.

deny[msg] {
  input.kind == "Pod"
  c := input.spec.containers[_]
  endswith(c.image, ":latest")
  msg := sprintf("container %s uses :latest - pin a version", [c.name])
}

deny[msg] {
  input.kind == "Pod"
  c := input.spec.containers[_]
  not contains(c.image, ":")
  msg := sprintf("container %s image has no tag - pin a version", [c.name])
}
