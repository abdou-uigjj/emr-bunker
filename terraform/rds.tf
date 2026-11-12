# The primary EMR database: private, encrypted, deletion-protected,
# multi-AZ, autoscaling storage, credentials in Secrets Manager.

resource "random_password" "db_master" {
  length  = 32
  special = false
}

resource "aws_db_subnet_group" "emr" {
  name       = "emr-bunker-${var.clinic_name}"
  subnet_ids = [aws_subnet.private_a.id, aws_subnet.private_b.id]
}

resource "aws_secretsmanager_secret" "db_master" {
  name                    = "emr-bunker/${var.clinic_name}/db-master"
  kms_key_id              = aws_kms_key.rds.arn
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "db_master" {
  secret_id = aws_secretsmanager_secret.db_master.id
  secret_string = jsonencode({
    username = var.db_username
    password = random_password.db_master.result
  })
}

resource "aws_db_instance" "emr" {
  identifier     = "emr-bunker-${var.clinic_name}"
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = var.db_instance_class

  allocated_storage     = var.db_allocated_storage
  max_allocated_storage = var.db_max_allocated_storage
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = aws_kms_key.rds.arn

  db_name  = "openemr"
  username = var.db_username
  password = random_password.db_master.result

  db_subnet_group_name   = aws_db_subnet_group.emr.name
  vpc_security_group_ids = [aws_security_group.db.id]
  multi_az               = true
  publicly_accessible    = false

  backup_retention_period = var.backup_retention_days
  backup_window           = "01:00-02:00"
  maintenance_window      = "sun:05:00-sun:06:00"
  copy_tags_to_snapshot   = true
  deletion_protection     = true

  tags = {
    Name         = "emr-bunker-primary"
    "emr-bunker" = "backup"
  }

  lifecycle {
    ignore_changes = [password]
  }
}

# the break-glass parameter group: read-only at the engine level, used
# by the Lambda when it rebuilds the replica during an incident
resource "aws_db_parameter_group" "breakglass" {
  name   = "emr-bunker-breakglass"
  family = "mysql8.0"

  parameter {
    name  = "read_only"
    value = "1"
  }

  parameter {
    name  = "super_read_only"
    value = "1"
  }

  parameter {
    name  = "innodb_read_only"
    value = "1"
  }
}
