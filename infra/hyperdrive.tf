############################
# Hyperdrive over Workers VPC -> private CloudNativePG Postgres (probe W-CAP-01).
#
# Flow: Worker(env.HYPERDRIVE) -> Hyperdrive -> VPC Service -> existing
# cloudflared tunnel (var.wulf_tunnel_id) -> wulf-pg-rw.wulf-pg.svc:5432.
#
# Requires the cloudflare provider >= 5.13 (Workers VPC). The backing DB and the
# tunnel live in the Talos cluster (see ../../containers/talos-gitops/
# infrastructure/base/wulf-pg). cloudflared must have `warp-routing.enabled`.
############################

# The VPC Service: a TCP endpoint Hyperdrive can target, routed to the Postgres
# ClusterIP over the named tunnel.
resource "cloudflare_connectivity_directory_service" "wulf_pg" {
  account_id   = var.cloudflare_account_id
  name         = "${var.name_prefix}-pg"
  type         = "tcp"
  tcp_port     = 5432
  app_protocol = "postgresql"

  host = {
    ipv4 = var.hyperdrive_pg_host
    network = {
      tunnel_id = var.wulf_tunnel_id
    }
  }

  tls_settings = {
    # CloudNativePG presents a self-signed server cert; Cloudflare does not yet
    # support a custom CA for VPC services, so verification is disabled for this
    # throwaway research DB. Tighten to verify_ca once custom CAs are supported.
    cert_verification_mode = var.hyperdrive_cert_mode
  }
}

# Hyperdrive config in VPC mode: origin.service_id references the VPC Service
# instead of host/port. user/password/database come from the CNPG-generated
# secret (wulf-pg-app).
resource "cloudflare_hyperdrive_config" "wulf_pg" {
  account_id = var.cloudflare_account_id
  name       = "${var.name_prefix}-hyperdrive"

  origin = {
    scheme     = "postgres"
    database   = var.hyperdrive_pg_database
    user       = var.hyperdrive_pg_user
    password   = var.hyperdrive_pg_password
    service_id = cloudflare_connectivity_directory_service.wulf_pg.id
  }
}
