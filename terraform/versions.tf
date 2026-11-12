terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # state lives in a private bucket the clinic controls; the bucket and
  # table are created once by hand before the first apply
  backend "s3" {}
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      project     = "emr-bunker"
      managed-by  = "terraform"
      description = "ransomware-proof OpenEMR for rural clinics"
    }
  }
}
