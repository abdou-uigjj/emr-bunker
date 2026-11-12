# Quarantine kit - pre-built so an incident is a swap, not a scramble.
#
# aws-quarantine: zero inbound, zero outbound. Attaching it to the
# primary's ENIs severs every connection within seconds - the network
# equivalent of pulling the plug, without walking to the closet.
#
# aws-breakglass: lets the break-glass replica talk to the EKS nodes
# and nothing else.

resource "aws_security_group" "quarantine" {
  name        = "aws-quarantine"
  description = "zero rules - attach to sever everything (emr-bunker)"
  vpc_id      = aws_vpc.emr.id

  lifecycle {
    # a rules change here is an incident-response change; make it loud
    create_before_destroy = true
  }
}

resource "aws_security_group" "breakglass" {
  name        = "aws-breakglass"
  description = "break-glass replica: EKS nodes only (emr-bunker)"
  vpc_id      = aws_vpc.emr.id
}

resource "aws_vpc_security_group_ingress_rule" "breakglass_from_app" {
  security_group_id            = aws_security_group.breakglass.id
  referenced_security_group_id = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = 3306
  to_port                      = 3306
  description                  = "read-only mysql from app nodes"
}

# SNS page the on-call gets the second the Lambda isolates the primary
resource "aws_sns_topic" "incident_page" {
  name              = "emr-bunker-incident-${var.clinic_name}"
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "oncall_email" {
  count     = var.oncall_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.incident_page.arn
  protocol  = "email"
  endpoint  = var.oncall_email
}
