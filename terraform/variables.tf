variable "region" {
  description = "AWS region for every resource"
  type        = string
  default     = "eu-west-3"
}

variable "clinic_name" {
  description = "Short clinic slug used in resource names"
  type        = string
  default     = "rural-clinic"
}

variable "admin_cidr" {
  description = "CIDR allowed to reach the bastion/SSM. Keep narrow."
  type        = string
  default     = "10.99.0.0/16"
}

variable "vpc_cidr" {
  description = "VPC CIDR - private subnets only"
  type        = string
  default     = "10.40.0.0/16"
}

variable "db_username" {
  description = "OpenEMR master username (password comes from Secrets Manager)"
  type        = string
  default     = "emradmin"
}

variable "db_instance_class" {
  description = "RDS instance class - burstable Graviton is enough for a clinic"
  type        = string
  default     = "db.t4g.medium"
}

variable "db_allocated_storage" {
  description = "Initial gp3 storage GiB"
  type        = number
  default     = 50
}

variable "db_max_allocated_storage" {
  description = "Storage autosave ceiling GiB"
  type        = number
  default     = 200
}

variable "backup_retention_days" {
  description = "RDS point-in-time retention (days)"
  type        = number
  default     = 14
}

variable "vault_min_retention_days" {
  description = "Backup Vault Lock minimum retention - the ransomware wall"
  type        = number
  default     = 90
}

variable "guardduty_min_severity" {
  description = "EventBridge forwards findings at/above this severity to the Lambda"
  type        = number
  default     = 7
}

variable "oncall_email" {
  description = "On-call email paged when the Lambda isolates the primary"
  type        = string
  default     = ""
}

variable "openemr_image" {
  description = "OpenEMR container image"
  type        = string
  default     = "openemr/openemr:7.0.2"
}
