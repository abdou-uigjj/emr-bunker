# Private-only VPC: no internet gateway, no NAT. Everything talks to AWS
# services through VPC endpoints; the clinic workload never gets a
# public IP, so there is nothing for a scanner to find.

resource "aws_vpc" "emr" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "emr-bunker-${var.clinic_name}" }
}

resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.emr.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, 0)
  availability_zone = "${var.region}a"

  tags = { Name = "emr-bunker-private-a" }
}

resource "aws_subnet" "private_b" {
  vpc_id            = aws_vpc.emr.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, 1)
  availability_zone = "${var.region}b"

  tags = { Name = "emr-bunker-private-b" }
}

# the EKS control plane ENIs land here
resource "aws_subnet" "control_a" {
  vpc_id            = aws_vpc.emr.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, 2)
  availability_zone = "${var.region}a"

  tags = { Name = "emr-bunker-control-a" }
}

resource "aws_subnet" "control_b" {
  vpc_id            = aws_vpc.emr.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, 3)
  availability_zone = "${var.region}b"

  tags = { Name = "emr-bunker-control-b" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.emr.id

  tags = { Name = "emr-bunker-private" }
}

resource "aws_route_table_association" "private" {
  for_each = {
    a = aws_subnet.private_a
    b = aws_subnet.private_b
    c = aws_subnet.control_a
    d = aws_subnet.control_b
  }
  subnet_id      = each.value.id
  route_table_id = aws_route_table.private.id
}

# ----------------------------------------------------------------------
# the app security group: only the EKS nodes talk to the database
# ----------------------------------------------------------------------
resource "aws_security_group" "app" {
  name        = "emr-bunker-app"
  description = "OpenEMR workload - EKS nodes only"
  vpc_id      = aws_vpc.emr.id
}

resource "aws_security_group" "db" {
  name        = "emr-bunker-db"
  description = "Postgres/MySQL from the EKS nodes only"
  vpc_id      = aws_vpc.emr.id
}

resource "aws_vpc_security_group_ingress_rule" "db_from_app" {
  security_group_id            = aws_security_group.db.id
  referenced_security_group_id = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = 3306
  to_port                      = 3306
  description                  = "mysql from app nodes"
}

# ----------------------------------------------------------------------
# VPC endpoints: the private VPC reaches AWS services without any NAT
# ----------------------------------------------------------------------

locals {
  interface_services = [
    "com.amazonaws.${var.region}.ecr.api",
    "com.amazonaws.${var.region}.ecr.dkr",
    "com.amazonaws.${var.region}.logs",
    "com.amazonaws.${var.region}.monitoring",
    "com.amazonaws.${var.region}.sts",
    "com.amazonaws.${var.region}.ssm",
    "com.amazonaws.${var.region}.ssmmessages",
    "com.amazonaws.${var.region}.ec2messages",
    "com.amazonaws.${var.region}.secretsmanager",
    "com.amazonaws.${var.region}.backup",
  ]
}

resource "aws_security_group" "endpoints" {
  name        = "emr-bunker-endpoints"
  description = "interface endpoints accept 443 from inside the vpc"
  vpc_id      = aws_vpc.emr.id
}

resource "aws_vpc_security_group_ingress_rule" "endpoints_443" {
  security_group_id = aws_security_group.endpoints.id
  cidr_ipv4         = var.vpc_cidr
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.emr.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  tags = { Name = "emr-bunker-s3-gateway" }
}

resource "aws_vpc_endpoint" "interface" {
  for_each = toset(local.interface_services)

  vpc_id              = aws_vpc.emr.id
  service_name        = each.value
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true

  tags = { Name = "emr-bunker-${each.value}" }
}
