# callbackd

Single-binary callback receiver for the wulf probes.

It listens on:

- `:80` for HTTP callbacks and ACME HTTP-01 challenges
- `:443` for HTTPS and WSS callbacks
- `:53/udp` and `:53/tcp` as the authoritative DNS server for the delegated exfil zone

Every event is appended to `*.jsonl` under `WULF_LOG_DIR` and also uploaded to R2 as one JSON object per event.

## Required environment

```bash
WULF_CALLBACK_DOMAIN=callback target parent domain, e.g. wulf.shart.cloud
WULF_DNS_ZONE=delegated DNS zone, e.g. x.wulf.shart.cloud
WULF_DNS_ANSWER_IPV4=157.245.210.122
WULF_R2_BUCKET=wulf-callback-events
WULF_R2_ACCOUNT_ID=<cloudflare account id>
WULF_R2_ACCESS_KEY_ID=<r2 key>
WULF_R2_SECRET_ACCESS_KEY=<r2 secret>
```

Optional:

```bash
WULF_NAMESERVER_HOST=ns.wulf.shart.cloud
WULF_LOG_DIR=/var/log/wulf
WULF_AUTOCERT_DIR=/var/lib/wulf/autocert
WULF_UPLOAD_TIMEOUT=10s
WULF_BODY_LIMIT_BYTES=1048576
```

`WULF_CALLBACK_DOMAIN` should be the suffix without the `callback.` host label. For your current Terraform shape, that means `wulf.shart.cloud`, not `callback.wulf.shart.cloud`.

## Build

```bash
go build ./...
```

## Run under systemd

Bind to privileged ports either as root or with `CAP_NET_BIND_SERVICE`.

Example service command:

```bash
/usr/local/bin/callbackd
```
