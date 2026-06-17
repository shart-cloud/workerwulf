############################
# KV — single namespace shared by Tracks 1 & 2 for binding-discovery tests.
############################
resource "cloudflare_workers_kv_namespace" "prey" {
  account_id = var.cloudflare_account_id
  title      = "${var.name_prefix}-kv"
}

############################
# R2 — two buckets:
#   research_findings: optional analytics offload (DuckDB sources)
#   callback_events:   target for the VPS receivers to ship JSONL events to
############################
resource "cloudflare_r2_bucket" "research_findings" {
  account_id = var.cloudflare_account_id
  name       = "${var.name_prefix}-research-findings"
  location   = var.r2_location
}

resource "cloudflare_r2_bucket" "callback_events" {
  account_id = var.cloudflare_account_id
  name       = "${var.name_prefix}-callback-events"
  location   = var.r2_location
}

############################
# D1 — research database used as a binding-discovery target.
############################
resource "cloudflare_d1_database" "prey" {
  account_id = var.cloudflare_account_id
  name       = "${var.name_prefix}-d1"

  # Provider v5 sends `read_replication: null` on update, which the API
  # rejects with HTTP 400. Ignore drift on it until the provider is fixed.
  lifecycle {
    ignore_changes = [read_replication]
  }
}

# Out of scope for v1 — flagged in README.md:
#   - cloudflare_workers_script for prey-worker + dynamic-parent (handled by `wrangler deploy`)
#   - cloudflare_tail_worker / observability bindings
#   - cloudflare_durable_object_namespace (Track 3 — separate Worker)
#   - cloudflare_queue, cloudflare_analytics_engine_dataset
#   - cloudflare_logpush_job
