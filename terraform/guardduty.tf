# GuardDuty: the detection half of the canary story.
#
# RDS login events feed GuardDuty with the anomaly signals it needs to
# spot credential abuse on the database; EKS runtime monitoring covers
# the container side. An EventBridge rule forwards any finding at or
# above var.guardduty_min_severity straight to the response Lambda.

resource "aws_guardduty_detector" "emr" {
  enable = true

  datasources {
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  tags = { Name = "emr-bunker-${var.clinic_name}" }
}

# RDS Protection (v5 provider: per-feature resources)
resource "aws_guardduty_detector_feature" "rds_login_events" {
  detector_id = aws_guardduty_detector.emr.id
  name        = "RDS_LOGIN_EVENTS"
  status      = "ENABLED"
}

# S3 data events cover the document store buckets
resource "aws_guardduty_detector_feature" "s3_data_events" {
  detector_id = aws_guardduty_detector.emr.id
  name        = "S3_DATA_EVENTS"
  status      = "ENABLED"
}

# EKS Protection
resource "aws_guardduty_detector_feature" "eks_runtime_monitoring" {
  detector_id = aws_guardduty_detector.emr.id
  name        = "EKS_RUNTIME_MONITORING"
  status      = "ENABLED"

  additional_configuration {
    name   = "EKS_ADDON_MANAGEMENT"
    status = "ENABLED"
  }
}

resource "aws_guardduty_detector_feature" "eks_audit_logs" {
  detector_id = aws_guardduty_detector.emr.id
  name        = "EKS_AUDIT_LOGS"
  status      = "ENABLED"
}

# ----------------------------------------------------------------------
# EventBridge: severity gate -> response Lambda
# ----------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "guardduty_high" {
  name        = "emr-bunker-guardduty-high"
  description = "GuardDuty findings at or above severity ${var.guardduty_min_severity}"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ "numeric" : [">=", var.guardduty_min_severity] }]
    }
  })
}

resource "aws_cloudwatch_event_target" "response_lambda" {
  rule      = aws_cloudwatch_event_rule.guardduty_high.name
  target_id = "emr-bunker-response"
  arn       = aws_lambda_function.response.arn
}

resource "aws_lambda_permission" "guardduty" {
  statement_id  = "allow-eventbridge-invoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.response.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_high.arn
}
