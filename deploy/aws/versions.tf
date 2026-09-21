terraform {
  required_version = ">= 1.5"
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.60" }
    tls    = { source = "hashicorp/tls", version = "~> 4.0" }
    local  = { source = "hashicorp/local", version = "~> 2.5" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "aws" {
  region  = var.region
  profile = var.profile
  default_tags {
    tags = { Project = "zanskar-test", ManagedBy = "terraform", Owner = var.owner }
  }
}
