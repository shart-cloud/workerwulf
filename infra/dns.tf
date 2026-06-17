############################
# DNS records in Cloudflare for the wulf subdomain. The parent zone is
# already on Cloudflare nameservers; rather than cross-delegating to
# DigitalOcean we publish everything here.
############################

# callback.<callback_domain> -> droplet (HTTP/WS receivers)
resource "cloudflare_dns_record" "callback_a" {
  zone_id = var.cloudflare_zone_id
  type    = "A"
  name    = "callback.${var.callback_domain}"
  content = digitalocean_droplet.callback.ipv4_address
  ttl     = 60
  proxied = false
}

# ns.<callback_domain> -> droplet (used as nameserver target by the NS delegation below)
resource "cloudflare_dns_record" "ns_host_a" {
  zone_id = var.cloudflare_zone_id
  type    = "A"
  name    = "ns.${var.callback_domain}"
  content = digitalocean_droplet.callback.ipv4_address
  ttl     = 60
  proxied = false
}

# <dns_exfil_subdomain>.<callback_domain> NS -> ns.<callback_domain>
# Delegates the exfil subdomain to the callback host's authoritative DNS.
resource "cloudflare_dns_record" "exfil_ns_delegation" {
  zone_id = var.cloudflare_zone_id
  type    = "NS"
  name    = "${var.dns_exfil_subdomain}.${var.callback_domain}"
  content = "ns.${var.callback_domain}"
  ttl     = 60
  proxied = false
}
