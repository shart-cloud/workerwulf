# Wave 6 target image for the W-CTR-* Cloudflare Containers `exec()` probes.
# See docs/wave6-containers-exec.md.
#
# Build + push:
#   docker build --network=host -t wulf-container:v1 ./container
#
# --network=host is needed on the WSL2 dev host: on the default Docker bridge,
# deb.debian.org resolves AAAA-only with no working IPv6 route, so every apt
# InRelease fetch is downloaded and then ignored, and the layer eventually fails
# ("Unable to locate package curl"). With host networking the same layer completes in
# seconds. Harmless elsewhere.
#   wrangler containers push registry.cloudflare.com/<acct>/wulf-container:v1
FROM debian:bookworm-slim

# The toolset is deliberately ordinary — this image is a stand-in for the kind of
# media/utility container a real Worker would call `exec()` into, not a purpose-built
# attack image. Nothing here is privileged or unusual:
#   ffmpeg          - the request-body -> stdin consumer (W-CTR-03)
#   curl            - egress + interception observation (W-CTR-05, W-CTR-10)
#   busybox         - httpd (a listener for W-CTR-11) and nc (raw TCP for W-CTR-05)
#   procps, iproute2- process table + interface enumeration (W-CTR-01/06/07)
#   ca-certificates - TLS egress
# ForceIPv4: deb.debian.org resolves to AAAA-only inside the default Docker bridge on
# the WSL2 build host, which has no IPv6 route — apt otherwise hangs on every
# InRelease fetch and eventually fails the layer. Harmless on IPv6-capable hosts.
RUN printf 'Acquire::ForceIPv4 "true";\n' > /etc/apt/apt.conf.d/99force-ipv4 \
    && apt-get update && apt-get install -y --no-install-recommends \
      ffmpeg \
      curl \
      busybox \
      procps \
      iproute2 \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Served by the long-running listener below. The canary proves, in W-CTR-11, that a
# `getTcpPort()` Fetcher reached THIS container rather than some other origin.
RUN mkdir -p /srv \
    && printf '{"listener":"busybox-httpd","port":8080,"canary":"flag{w-ctr-11-declared-port}"}' \
       > /srv/index.html

# A benign, non-secret marker written into the image at build time. W-CTR-09 uses a
# *runtime*-written file under /tmp instead; this one exists so a snapshot restore can
# be distinguished from a plain fresh image start.
RUN printf 'flag{w-ctr-09-image-baseline}\n' > /srv/baseline.txt

# The container must be RUNNING for exec() to work — `exec()` does not start a stopped
# container. A tiny always-on listener is the least-surprising way to keep it up, and
# doubles as the declared-port target for W-CTR-11.
EXPOSE 8080
CMD ["busybox", "httpd", "-f", "-p", "8080", "-h", "/srv"]
