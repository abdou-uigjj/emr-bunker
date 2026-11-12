# Response Lambda: runs the proven five-move playbook from
# playbook/core.py through the AWS control plane.

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "response" {
  name               = "emr-bunker-response-${var.clinic_name}"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "response" {
  statement {
    sid    = "isolateAndRestore"
    effect = "Allow"
    actions = [
      "rds:ModifyDBInstance",
      "rds:DescribeDBInstances",
      "rds:CreateDBSnapshot",
      "rds:RestoreDBInstanceFromDBSnapshot",
      "rds:DescribeDBSnapshots",
      "rds:ListTagsForResource",
    ]
    resources = [
      aws_db_instance.emr.arn,
      "arn:aws:rds:${var.region}:${data.aws_caller_identity.current.account_id}:snapshot:emr-bunker-*",
      aws_db_parameter_group.breakglass.arn,
    ]
  }

  statement {
    sid    = "page"
    effect = "Allow"
    actions = [
      "sns:Publish",
    ]
    resources = [aws_sns_topic.incident_page.arn]
  }

  statement {
    sid    = "evidence"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = [
      aws_secretsmanager_secret.vault_key.arn,
      "arn:aws:logs:${var.region}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/emr-bunker-response-*",
    ]
  }
}

resource "aws_iam_role_policy" "response" {
  name   = "emr-bunker-response"
  role   = aws_iam_role.response.id
  policy = data.aws_iam_policy_document.response.json
}

resource "aws_secretsmanager_secret" "vault_key" {
  name                    = "emr-bunker/${var.clinic_name}/vault-key"
  kms_key_id              = aws_kms_key.rds.arn
  recovery_window_in_days = 7
}

resource "aws_cloudwatch_log_group" "response" {
  name              = "/aws/lambda/emr-bunker-response-${var.clinic_name}"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.rds.arn
}

data "aws_caller_identity" "current" {}

locals {
  lambda_zip = "${path.module}/../lambda.zip"
}

resource "aws_lambda_function" "response" {
  function_name = "emr-bunker-response-${var.clinic_name}"
  role          = aws_iam_role.response.arn
  runtime       = "python3.12"
  handler       = "lambda/response/handler.handler"
  timeout       = 120
  memory_size   = 256

  # handler.py + playbook/ + canary/ zip, built by `make lambda.zip`
  filename         = local.lambda_zip
  source_code_hash = try(filebase64sha256(local.lambda_zip), null)

  vpc_config {
    subnet_ids         = [aws_subnet.private_a.id, aws_subnet.private_b.id]
    security_group_ids = [aws_security_group.endpoints.id]
  }

  environment {
    variables = {
      EMR_BUNKER_DB_ID          = aws_db_instance.emr.identifier
      EMR_BUNKER_QUARANTINE_SGS = aws_security_group.quarantine.id
      EMR_BUNKER_BREAKGLASS_SGS = aws_security_group.breakglass.id
      EMR_BUNKER_BREAKGLASS_PG  = aws_db_parameter_group.breakglass.name
      EMR_BUNKER_RESTORE_ID     = "emr-breakglass-${var.clinic_name}"
      EMR_BUNKER_PAGE_TOPIC     = aws_sns_topic.incident_page.arn
      EMR_BUNKER_VAULT_KEY      = aws_secretsmanager_secret.vault_key.arn
      EMR_BUNKER_VAULT_ROOT     = "/tmp/emr-bunker-vault"
      EMR_BUNKER_MIN_SEVERITY   = tostring(var.guardduty_min_severity)
    }
  }

  depends_on = [aws_cloudwatch_log_group.response]
}
