locals {
  callbackd_build_dir      = "${path.module}/.terraform/callbackd"
  callbackd_binary_path    = "${local.callbackd_build_dir}/callbackd"
  callbackd_binary_abspath = abspath(local.callbackd_binary_path)
  callbackd_unit_path      = "${path.module}/templates/callbackd.service"
  callbackd_pkg_dir        = abspath("${path.module}/../packages/callbackd")

  callbackd_source_files = [
    "${path.module}/../packages/callbackd/go.mod",
    "${path.module}/../packages/callbackd/go.sum",
    "${path.module}/../packages/callbackd/main.go",
  ]

  callbackd_source_hash = sha256(join("", [for f in local.callbackd_source_files : filesha256(f)]))

  callbackd_env = templatefile("${path.module}/templates/callbackd.env.tftpl", {
    callback_domain        = var.callback_domain
    dns_exfil_zone         = "${var.dns_exfil_subdomain}.${var.callback_domain}"
    nameserver_host        = "ns.${var.callback_domain}"
    dns_answer_ipv4        = digitalocean_droplet.callback.ipv4_address
    callback_events_bucket = cloudflare_r2_bucket.callback_events.name
    cloudflare_account_id  = var.cloudflare_account_id
    r2_access_key_id       = var.callback_r2_access_key_id
    r2_secret_access_key   = var.callback_r2_secret_access_key
    log_dir                = var.callback_log_dir
    autocert_dir           = var.callback_autocert_dir
  })

  callbackd_install_script = templatefile("${path.module}/templates/install-callbackd.sh.tftpl", {
    callback_log_dir      = var.callback_log_dir
    callback_state_dir    = dirname(var.callback_autocert_dir)
    callback_autocert_dir = var.callback_autocert_dir
  })
}

resource "terraform_data" "callbackd_build" {
  triggers_replace = {
    source_hash = local.callbackd_source_hash
  }

  provisioner "local-exec" {
    interpreter = ["/bin/bash", "-lc"]
    command     = "mkdir -p '${abspath(local.callbackd_build_dir)}' && go build -o '${local.callbackd_binary_abspath}' '${local.callbackd_pkg_dir}'"
  }
}

resource "terraform_data" "callbackd_deploy" {
  triggers_replace = {
    droplet_id   = tostring(digitalocean_droplet.callback.id)
    source_hash  = local.callbackd_source_hash
    unit_hash    = filesha256(local.callbackd_unit_path)
    env_hash     = sha256(nonsensitive(local.callbackd_env))
    install_hash = sha256(local.callbackd_install_script)
  }

  depends_on = [
    digitalocean_firewall.callback,
    terraform_data.callbackd_build,
  ]

  connection {
    type        = "ssh"
    host        = digitalocean_droplet.callback.ipv4_address
    user        = "root"
    private_key = file(pathexpand(var.ssh_private_key_path))
    timeout     = "2m"
  }

  provisioner "file" {
    source      = local.callbackd_binary_abspath
    destination = "/tmp/callbackd"
  }

  provisioner "file" {
    content     = local.callbackd_env
    destination = "/tmp/callbackd.env"
  }

  provisioner "file" {
    source      = local.callbackd_unit_path
    destination = "/tmp/callbackd.service"
  }

  provisioner "file" {
    content     = local.callbackd_install_script
    destination = "/tmp/install-callbackd.sh"
  }

  provisioner "remote-exec" {
    inline = [
      "chmod 0700 /tmp/install-callbackd.sh",
      "/tmp/install-callbackd.sh",
      "install -o root -g root -m 0755 /tmp/callbackd /usr/local/bin/callbackd",
      "install -d -o root -g root -m 0755 /etc/wulf",
      "install -o root -g root -m 0600 /tmp/callbackd.env /etc/wulf/callbackd.env",
      "install -o root -g root -m 0644 /tmp/callbackd.service /etc/systemd/system/callbackd.service",
      "systemctl daemon-reload",
      "systemctl enable --now callbackd.service",
      "systemctl restart callbackd.service",
      "systemctl is-active --quiet callbackd.service",
    ]
  }
}
