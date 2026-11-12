# KMS - one key per duty, no sharing, rotation on.

resource "aws_kms_key" "rds" {
  description             = "emr-bunker RDS storage encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "rds" {
  name          = "alias/emr-bunker-rds-${var.clinic_name}"
  target_key_id = aws_kms_key.rds.key_id
}

resource "aws_kms_key" "backup" {
  description             = "emr-bunker backup vault encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "backup" {
  name          = "alias/emr-bunker-backup-${var.clinic_name}"
  target_key_id = aws_kms_key.backup.key_id
}

resource "aws_kms_key" "eks_secrets" {
  description             = "emr-bunker EKS envelope encryption for k8s secrets"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

resource "aws_kms_alias" "eks_secrets" {
  name          = "alias/emr-bunker-eks-secrets-${var.clinic_name}"
  target_key_id = aws_kms_key.eks_secrets.key_id
}
