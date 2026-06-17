############################
# Callback receiver VPS.
# Hosts: HTTP receiver (80/443), authoritative DNS for the exfil subdomain
# (53/udp+tcp), WebSocket echo (443), raw TCP listener (variable port).
# Receivers append JSON lines locally and ship to R2 callback_events bucket.
############################

resource "digitalocean_ssh_key" "admin" {
  name       = "${var.name_prefix}-admin"
  public_key = file(pathexpand(var.ssh_public_key_path))
}

resource "digitalocean_droplet" "callback" {
  name     = "${var.name_prefix}-callback"
  region   = var.do_region
  size     = var.do_droplet_size
  image    = var.do_image
  ssh_keys = [digitalocean_ssh_key.admin.fingerprint]

  # cloud-init is intentionally minimal — receivers are deployed via a
  # separate step (Ansible / rsync / Pulumi) once the host exists. This file
  # only guarantees ssh-in and unattended-upgrades.
  user_data = <<-CLOUDINIT
    #cloud-config
    package_update: true
    package_upgrade: true
    packages:
      - ca-certificates
      - curl
      - jq
      - unattended-upgrades
    write_files:
      - path: /etc/wulf/README
        content: |
          This host is the wulf callback receiver. Receivers are deployed
          out-of-band. See infra/README.md.
    runcmd:
      - systemctl enable --now unattended-upgrades
  CLOUDINIT

  tags = ["wulf", "callback"]
}

resource "digitalocean_firewall" "callback" {
  name        = "${var.name_prefix}-callback"
  droplet_ids = [digitalocean_droplet.callback.id]

  # SSH — restrict to admin CIDRs
  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = var.admin_cidrs
  }

  # HTTP / HTTPS callback + WebSocket echo
  inbound_rule {
    protocol         = "tcp"
    port_range       = "80"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }
  inbound_rule {
    protocol         = "tcp"
    port_range       = "443"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # DNS authoritative (delegated subdomain)
  inbound_rule {
    protocol         = "udp"
    port_range       = "53"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }
  inbound_rule {
    protocol         = "tcp"
    port_range       = "53"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Allow all egress
  outbound_rule {
    protocol              = "tcp"
    port_range            = "all"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
  outbound_rule {
    protocol              = "udp"
    port_range            = "all"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
  outbound_rule {
    protocol              = "icmp"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

# DNS is managed in Cloudflare (see dns.tf) — the parent zone shart.cloud
# is on Cloudflare nameservers, so we publish records there instead of
# delegating wulf.shart.cloud to DigitalOcean.
