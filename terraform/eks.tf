# EKS - private control plane, KMS-encrypted secrets, the canary
# sidecar ships on the OpenEMR pods.

data "aws_iam_policy_document" "eks_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "eks_cluster" {
  name               = "emr-bunker-eks-cluster-${var.clinic_name}"
  assume_role_policy = data.aws_iam_policy_document.eks_assume.json
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

data "aws_iam_policy_document" "eks_nodes_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "eks_nodes" {
  name               = "emr-bunker-eks-nodes-${var.clinic_name}"
  assume_role_policy = data.aws_iam_policy_document.eks_nodes_assume.json
}

resource "aws_iam_role_policy_attachment" "nodes_worker" {
  role       = aws_iam_role.eks_nodes.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "nodes_cni" {
  role       = aws_iam_role.eks_nodes.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "nodes_ecr" {
  role       = aws_iam_role.eks_nodes.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_role_policy_attachment" "nodes_ssm" {
  role       = aws_iam_role.eks_nodes.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_cloudwatch_log_group" "eks" {
  name              = "/aws/eks/emr-bunker-${var.clinic_name}/cluster"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.rds.arn
}

resource "aws_eks_cluster" "emr" {
  name     = "emr-bunker-${var.clinic_name}"
  role_arn = aws_iam_role.eks_cluster.arn
  version  = "1.31"

  vpc_config {
    subnet_ids              = [aws_subnet.control_a.id, aws_subnet.control_b.id]
    endpoint_public_access  = false
    endpoint_private_access = true
    security_group_ids      = []
  }

  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = aws_kms_key.eks_secrets.arn
    }
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator"]

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy,
    aws_cloudwatch_log_group.eks,
  ]
}

resource "aws_eks_node_group" "emr" {
  cluster_name    = aws_eks_cluster.emr.name
  node_group_name = "emr-bunker-app"
  node_role_arn   = aws_iam_role.eks_nodes.arn

  subnet_ids     = [aws_subnet.private_a.id, aws_subnet.private_b.id]
  instance_types = ["t4g.medium"]
  capacity_type  = "ON_DEMAND"

  scaling_config {
    desired_size = 2
    min_size     = 2
    max_size     = 4
  }

  # the response Lambda quarantines by security group; nodes carry the
  # app SG so the db SG can scope to it
  remote_access {
    ec2_ssh_key               = ""
    source_security_group_ids = []
  }

  labels = {
    workload = "openemr"
  }

  tags = {
    "emr-bunker" = "backup"
  }

  depends_on = [
    aws_iam_role_policy_attachment.nodes_worker,
    aws_iam_role_policy_attachment.nodes_cni,
    aws_iam_role_policy_attachment.nodes_ecr,
  ]
}
