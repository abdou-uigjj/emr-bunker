# The ransomware wall.
#
# Backup Vault Lock in COMPLIANCE mode: once the lock cools down
# (changeable_for_days), NOBODY - not the root user, not an admin who
# phished their way in, not a ransomware crew that owns the account -
# can delete or shorten retention on backups inside the vault for the
# locked window. This is the control the whole plan leans on.
#
# terraform note: aws_backup_vault_lock_configuration has no `mode`
# argument - setting changeable_for_days is what selects COMPLIANCE
# mode (a governance-mode lock simply omits it).

resource "aws_backup_vault" "emr" {
  name        = "emr-bunker-${var.clinic_name}"
  kms_key_arn = aws_kms_key.backup.arn
}

resource "aws_backup_vault_lock_configuration" "emr" {
  backup_vault_name   = aws_backup_vault.emr.name
  min_retention_days  = var.vault_min_retention_days
  changeable_for_days = 7
}

resource "aws_backup_plan" "emr" {
  name = "emr-bunker-${var.clinic_name}"

  # Rule 1: daily vault backups - the copies ransomware cannot touch
  rule {
    rule_name         = "daily-vault"
    target_vault_name = aws_backup_vault.emr.name
    schedule          = "cron(0 3 * * ? *)"

    lifecycle {
      delete_after = var.vault_min_retention_days
    }

    copy_action {
      destination_vault_arn = aws_backup_vault.emr.arn
    }
  }

  # Rule 2: weekly - kept the full locked window
  rule {
    rule_name         = "weekly-vault"
    target_vault_name = aws_backup_vault.emr.name
    schedule          = "cron(0 4 ? * SUN *)"

    lifecycle {
      delete_after = var.vault_min_retention_days * 2
    }
  }
}

resource "aws_backup_selection" "emr" {
  iam_role_arn = aws_iam_role.backup.arn
  name         = "emr-bunker-${var.clinic_name}"
  plan_id      = aws_backup_plan.emr.id
  selection_tag {
    type  = "STRINGEQUALS"
    key   = "emr-bunker"
    value = "backup"
  }
}

resource "aws_backup_region_settings" "emr" {
  resource_type_opt_in_preference = {
    "Aurora"         = true
    "DynamoDB"       = true
    "EBS"            = true
    "EC2"            = true
    "EFS"            = true
    "RDS"            = true
    "S3"             = true
    "StorageGateway" = true
  }
}

data "aws_iam_policy_document" "backup_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["backup.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "backup" {
  name               = "emr-bunker-backup-${var.clinic_name}"
  assume_role_policy = data.aws_iam_policy_document.backup_assume.json
}

resource "aws_iam_role_policy_attachment" "backup" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_iam_role_policy_attachment" "restore" {
  role       = aws_iam_role.backup.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
}
