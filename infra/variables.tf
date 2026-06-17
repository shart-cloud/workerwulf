variable "cloudflare_api_token" {
  description = "Cloudflare API token with Workers, R2, D1, KV edit permissions."
  type        = string
  sensitive   = true
}

variable "cloudflare_account_id" {
  description = "Cloudflare account ID hosting all wulf resources."
  type        = string
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone ID for the parent zone (e.g. shart.cloud) where wulf DNS records are created."
  type        = string
}

variable "digitalocean_api_token" {
  description = "DigitalOcean API token for droplet + DNS provisioning."
  type        = string
  sensitive   = true
}

variable "name_prefix" {
  description = "Resource name prefix. Override for parallel deployments."
  type        = string
  default     = "wulf"
}

variable "do_region" {
  description = "DigitalOcean region for the callback VPS."
  type        = string
  default     = "nyc3"
}

variable "do_droplet_size" {
  description = "Droplet size slug. The receivers are tiny; s-1vcpu-1gb is enough."
  type        = string
  default     = "s-1vcpu-1gb"
}

variable "do_image" {
  description = "DigitalOcean image slug for the callback host."
  type        = string
  default     = "ubuntu-24-04-x64"
}

variable "ssh_public_key_path" {
  description = "Path to the SSH public key file authorized to log in to the callback host (e.g. ~/.ssh/id_ed25519.pub)."
  type        = string
}

variable "ssh_private_key_path" {
  description = "Path to the SSH private key file Terraform uses to deploy callbackd to the callback host."
  type        = string
  default     = "~/.ssh/id_ed25519"
}

variable "admin_cidrs" {
  description = "CIDRs allowed to SSH to the callback host (default: anywhere; tighten before apply)."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "callback_domain" {
  description = "FQDN suffix for callback hosts (e.g. wulf.shart.cloud). Must be a subdomain inside the Cloudflare zone identified by cloudflare_zone_id."
  type        = string
}

variable "dns_exfil_subdomain" {
  description = "Subdomain whose NS is delegated to the callback host for DNS-based exfil tests."
  type        = string
  default     = "x"
}

variable "r2_location" {
  description = "R2 location hint (auto leaves Cloudflare to pick)."
  type        = string
  default     = "enam"
}

variable "callback_r2_access_key_id" {
  description = "R2 API access key ID used by callbackd to upload callback events."
  type        = string
  sensitive   = true
}

variable "callback_r2_secret_access_key" {
  description = "R2 API secret access key used by callbackd to upload callback events."
  type        = string
  sensitive   = true
}

variable "callback_log_dir" {
  description = "Directory on the callback host where callbackd appends JSONL event logs."
  type        = string
  default     = "/var/log/wulf"
}

variable "callback_autocert_dir" {
  description = "Directory on the callback host where callbackd stores ACME state and certificates."
  type        = string
  default     = "/var/lib/wulf/autocert"
}

############################
# Hyperdrive / Workers VPC (probe W-CAP-01). See hyperdrive.tf.
############################

variable "wulf_tunnel_id" {
  description = "UUID of the existing cloudflared tunnel in the Talos cluster that the Workers VPC service routes through."
  type        = string
}

variable "hyperdrive_pg_host" {
  description = "Private address of the CNPG Postgres the VPC service targets, e.g. the wulf-pg-rw ClusterIP (kubectl get svc wulf-pg-rw -n wulf-pg -o jsonpath='{.spec.clusterIP}')."
  type        = string
}

variable "hyperdrive_pg_database" {
  description = "Database name on the backing Postgres."
  type        = string
  default     = "wulf"
}

variable "hyperdrive_pg_user" {
  description = "App user for the backing Postgres (CNPG secret wulf-pg-app .username)."
  type        = string
  sensitive   = true
}

variable "hyperdrive_pg_password" {
  description = "App password for the backing Postgres (CNPG secret wulf-pg-app .password)."
  type        = string
  sensitive   = true
}

variable "hyperdrive_cert_mode" {
  description = "VPC service TLS verification: verify_full | verify_ca | disabled. CNPG uses a self-signed CA and custom CAs are not yet supported, so 'disabled' for this research DB."
  type        = string
  default     = "disabled"
}
