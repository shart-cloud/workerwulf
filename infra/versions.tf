terraform {
  required_version = ">= 1.6.0"

  required_providers {
    cloudflare = {
      source = "cloudflare/cloudflare"
      # >= 5.13 required for Workers VPC (cloudflare_connectivity_directory_service)
      # used by hyperdrive.tf. Run `terraform init -upgrade` if the lock pins older.
      version = ">= 5.13, < 6.0"
    }
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.40"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Default: local state. For multi-machine work, switch to an R2 backend
  # once the wulf-callback bucket exists. See infra/README.md.
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

provider "digitalocean" {
  token = var.digitalocean_api_token
}
