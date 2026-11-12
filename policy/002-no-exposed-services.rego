package main

# 002 - the clinic has no public doors: no LoadBalancer, no NodePort.

deny[msg] {
  input.kind == "Service"
  input.spec.type == "LoadBalancer"
  msg := sprintf("service %s uses LoadBalancer - only ClusterIP is allowed", [input.metadata.name])
}

deny[msg] {
  input.kind == "Service"
  input.spec.type == "NodePort"
  msg := sprintf("service %s uses NodePort - only ClusterIP is allowed", [input.metadata.name])
}

deny[msg] {
  input.kind == "Ingress"
  msg := sprintf("ingress %s is forbidden - no public ingress in the clinic vpc", [input.metadata.name])
}
