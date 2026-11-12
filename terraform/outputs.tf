output "db_endpoint" {
  description = "Primary RDS endpoint (private)"
  value       = aws_db_instance.emr.address
}

output "db_secret_arn" {
  description = "Secrets Manager secret holding the master credentials"
  value       = aws_secretsmanager_secret.db_master.arn
}

output "backup_vault_name" {
  description = "Backup vault with the compliance lock"
  value       = aws_backup_vault.emr.name
}

output "backup_vault_lock_min_retention_days" {
  description = "Ransomware wall: shortest allowed retention in the vault"
  value       = aws_backup_vault_lock_configuration.emr.min_retention_days
}

output "quarantine_security_group" {
  description = "Zero-rule SG the Lambda attaches during an incident"
  value       = aws_security_group.quarantine.id
}

output "breakglass_param_group" {
  description = "Read-only parameter group for the break-glass replica"
  value       = aws_db_parameter_group.breakglass.name
}

output "eks_cluster_name" {
  value = aws_eks_cluster.emr.name
}

output "response_lambda" {
  value = aws_lambda_function.response.function_name
}

output "incident_page_topic" {
  value = aws_sns_topic.incident_page.arn
}
