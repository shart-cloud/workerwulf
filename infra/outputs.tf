############################
# Outputs feed wrangler.toml (for Worker deploy) and the harness config
# (for callback endpoint URLs).
############################

output "cloudflare_account_id" {
  value = var.cloudflare_account_id
}

output "kv_namespace_id" {
  description = "Wire into wrangler.toml [[kv_namespaces]].id for both Workers."
  value       = cloudflare_workers_kv_namespace.prey.id
}

output "r2_research_bucket" {
  value = cloudflare_r2_bucket.research_findings.name
}

output "r2_callback_events_bucket" {
  value = cloudflare_r2_bucket.callback_events.name
}

output "d1_database_id" {
  description = "Wire into wrangler.toml [[d1_databases]].database_id."
  value       = cloudflare_d1_database.prey.id
}

output "d1_database_name" {
  value = cloudflare_d1_database.prey.name
}

output "callback_host_ipv4" {
  value = digitalocean_droplet.callback.ipv4_address
}

output "callback_http_base" {
  description = "Base URL the harness/probes send HTTP callbacks to."
  value       = "http://callback.${var.callback_domain}"
}

output "dns_exfil_zone" {
  description = "Authoritative zone the callback host serves; encode data in subdomains."
  value       = "${var.dns_exfil_subdomain}.${var.callback_domain}"
}

output "hyperdrive_id" {
  description = "Wire into packages/worker/wrangler.toml [[hyperdrive]].id for probe W-CAP-01."
  value       = cloudflare_hyperdrive_config.wulf_pg.id
}
