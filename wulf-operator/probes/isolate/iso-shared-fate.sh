#!/usr/bin/env bash
# Driver for P-WL-ISO-002 (resource shared-fate) + P-WL-ISO-003 (cache isolation).
#
# Reproducible successor to F-1's ad-hoc kubectl drive. Generates SandboxWorker
# manifests from iso-shared-fate.js (single source of truth), applies them, then
# runs the shared-fate matrix from in-cluster ephemeral curl pods and prints a
# summary comparing the co-located (one pod, V8-isolate boundary) and separated
# (two pods, cgroup boundary) arrangements.
#
# Usage:
#   ./iso-shared-fate.sh render <dir>     # just write manifests, don't apply
#   ./iso-shared-fate.sh up               # apply manifests, wait for ready
#   ./iso-shared-fate.sh cache            # (c) cache-state isolation
#   ./iso-shared-fate.sh mem              # (d) memory shared-fate (OOM)
#   ./iso-shared-fate.sh cpu              # (d) CPU shared-fate (starvation)
#   ./iso-shared-fate.sh fd  <sink-url>   # (d) socket/fd flood (exploratory)
#   ./iso-shared-fate.sh all              # cache + mem + cpu
#   ./iso-shared-fate.sh down             # delete the workers
#
# Requires: kubectl with context on the target cluster.

set -uo pipefail

NS="${WULF_NS:-wulf-system}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROBE_JS="$SCRIPT_DIR/iso-shared-fate.js"
CURL_IMAGE="${CURL_IMAGE:-curlimages/curl:8.11.1}"
MEM_LIMIT="256Mi"

COLO="iso-shared-fate-colo"   # maxIsolates: 2  → isolate-0 :8080, isolate-1 :8081
SEP_A="iso-shared-fate-sep-a" # separated aggressor pod
SEP_V="iso-shared-fate-sep-v" # separated victim pod

# ── manifest generation (probe.js is the single source of truth) ────────────

# emit_worker NAME MAXISOLATES [CPU_LIMIT]  → one SandboxWorker manifest, probe inlined.
emit_worker() {
  local name="$1" max="$2" cpu="${3:-500m}"
  echo "apiVersion: wulf.jaredgore.com/v1alpha1"
  echo "kind: SandboxWorker"
  echo "metadata:"
  echo "  name: $name"
  echo "  namespace: $NS"
  echo "  labels:"
  echo "    wulf.jaredgore.com/track: isolate-boundary"
  echo "    wulf.jaredgore.com/probe-id: P-WL-ISO-002"
  echo "spec:"
  echo "  script:"
  echo "    inline: |"
  sed 's/^/      /' "$PROBE_JS"
  echo "  compatibilityDate: \"2024-09-23\""
  echo "  compatibilityFlags:"
  echo "    - nodejs_compat"
  echo "  bindings:"
  echo "    vars:"
  echo "      WORKER_NAME: $name"
  echo "      HARDENING_PROFILE: naked"
  echo "  hardening:"
  echo "    profile: naked"
  echo "  runtime:"
  if [ "$max" -gt 1 ]; then
    echo "    maxIsolates: $max"
  fi
  echo "    resources:"
  echo "      requests:"
  echo "        cpu: 100m"
  echo "        memory: 128Mi"
  echo "      limits:"
  echo "        cpu: $cpu"
  echo "        memory: $MEM_LIMIT"
  echo "  exposure:"
  echo "    type: ClusterIP"
  echo "    port: 8080"
}

render() {
  local dir="${1:-$SCRIPT_DIR/manifests}"
  mkdir -p "$dir"
  emit_worker "$COLO" 2 > "$dir/colo.yaml"
  emit_worker "$SEP_A" 1 > "$dir/sep-a.yaml"
  emit_worker "$SEP_V" 1 > "$dir/sep-v.yaml"
  echo "wrote manifests to $dir"
}

up() {
  local dir; dir="$(mktemp -d)"
  render "$dir" >/dev/null
  kubectl apply -f "$dir"
  echo "waiting for rollouts…"
  kubectl -n "$NS" rollout status "deploy/$COLO" --timeout=120s
  kubectl -n "$NS" rollout status "deploy/$SEP_A" --timeout=120s
  kubectl -n "$NS" rollout status "deploy/$SEP_V" --timeout=120s
}

down() {
  kubectl -n "$NS" delete sandboxworker "$COLO" "$SEP_A" "$SEP_V" --ignore-not-found
}

# ── in-cluster probe helpers ────────────────────────────────────────────────

# hit SVC PORT QUERY  → curl an isolate from an ephemeral in-cluster pod, echo body.
hit() {
  local svc="$1" port="$2" query="$3"
  local url="http://$svc.$NS.svc.cluster.local:$port/?$query"
  kubectl -n "$NS" run "p-$RANDOM" --image="$CURL_IMAGE" --restart=Never -i --rm \
    --quiet --command -- curl -s --max-time 30 "$url" 2>/dev/null
}

# restart_count NAME → containerStatuses[0].restartCount for the worker's pod.
restart_count() {
  kubectl -n "$NS" get pods -l "app.kubernetes.io/name=$1" \
    -o jsonpath='{.items[0].status.containerStatuses[0].restartCount}' 2>/dev/null
}

# term_reason NAME → lastState.terminated.reason (e.g. OOMKilled) for the pod.
term_reason() {
  kubectl -n "$NS" get pods -l "app.kubernetes.io/name=$1" \
    -o jsonpath='{.items[0].status.containerStatuses[0].lastState.terminated.reason}' 2>/dev/null
}

# ── (c) cache-state isolation ───────────────────────────────────────────────

run_cache() {
  local key="iso-cache-$RANDOM" secret="leak-canary-$RANDOM"
  echo "── (c) P-WL-ISO-003 cache-state isolation ──"
  echo "writing secret on COLO isolate-0 (:8080)…"
  hit "$COLO" 8080 "role=cache-write&key=$key&secret=$secret" | sed 's/^/  /'
  echo "reading same key on COLO isolate-1 (:8081) — leaked=true means shared cache:"
  hit "$COLO" 8081 "role=cache-read&key=$key" | sed 's/^/  /'
  echo "control: writing on SEP_A, reading on SEP_V (separate pods, must be found=false):"
  hit "$SEP_A" 8080 "role=cache-write&key=$key&secret=$secret" | sed 's/^/  /'
  hit "$SEP_V" 8080 "role=cache-read&key=$key" | sed 's/^/  /'
}

# ── (d) memory shared-fate ──────────────────────────────────────────────────

run_mem() {
  echo "── (d) P-WL-ISO-002 memory shared-fate ──"
  echo "COLO before: isolate-0 restart=$(restart_count "$COLO")"
  echo "firing 400MiB aggressor at COLO isolate-0 (:8080) — request will die on OOM…"
  hit "$COLO" 8080 "role=aggressor&resource=mem&mb=400" | sed 's/^/  /'
  sleep 8
  echo "COLO after: restart=$(restart_count "$COLO") reason=$(term_reason "$COLO")"
  echo "COLO victim on isolate-1 (:8081) — empty/restarted body = died with the pod:"
  hit "$COLO" 8081 "role=victim" | sed 's/^/  /'
  echo
  echo "SEP before: aggressor restart=$(restart_count "$SEP_A") victim restart=$(restart_count "$SEP_V")"
  echo "firing 400MiB aggressor at SEP_A…"
  hit "$SEP_A" 8080 "role=aggressor&resource=mem&mb=400" | sed 's/^/  /'
  sleep 8
  echo "SEP after: aggressor restart=$(restart_count "$SEP_A") reason=$(term_reason "$SEP_A") victim restart=$(restart_count "$SEP_V")"
  echo "SEP victim (separate pod) — should still be alive:"
  hit "$SEP_V" 8080 "role=victim" | sed 's/^/  /'
}

# ── (d) CPU shared-fate ─────────────────────────────────────────────────────

# cpu_pair fires two identical bursts CONCURRENTLY (URL $3 and URL $4) from one
# in-cluster pod and echoes "start_a end_a start_b end_b" (epoch ms, measured
# INSIDE each isolate around its compute loop). Overlap is the real CPU-contention
# signal: co-located isolates sharing one workerd execution thread SERIALIZE
# synchronous CPU work (overlap ≈ 0); isolates in separate pods/processes run in
# parallel (overlap ≈ full burst). work_ms alone can't see this — two serialized
# bursts each report their own throttled time and look identical to solo.
cpu_pair() {
  kubectl -n "$NS" run "cpu-$RANDOM" --image="$CURL_IMAGE" --restart=Never -i --rm \
    --quiet --command -- sh -c '
      curl -s "$1" > /tmp/a & curl -s "$2" > /tmp/b & wait
      f(){ grep -o "\"$2\":[0-9]*" "$1" | grep -o "[0-9]*$"; }
      echo "$(f /tmp/a started_at) $(f /tmp/a ended_at) $(f /tmp/b started_at) $(f /tmp/b ended_at)"
    ' _ "$1" "$2" 2>/dev/null
}

# cpu_report LABEL START_A END_A START_B END_B  → overlap + total wall.
cpu_report() {
  local label="$1" s0="${2:-}" e0="${3:-}" s1="${4:-}" e1="${5:-}"
  if [ -z "$s0$e0$s1$e1" ]; then echo "  $label (no data — pods up?)"; return; fi
  local d0=$((e0 - s0)) d1=$((e1 - s1))
  local ostart=$((s0 > s1 ? s0 : s1)) oend=$((e0 < e1 ? e0 : e1))
  local overlap=$((oend > ostart ? oend - ostart : 0))
  local tstart=$((s0 < s1 ? s0 : s1)) tend=$((e0 > e1 ? e0 : e1))
  printf "  %-36s burst_A=%sms burst_B=%sms overlap=%sms total_wall=%sms\n" \
    "$label" "$d0" "$d1" "$overlap" "$((tend - tstart))"
}

# enforce — CPU follow-on: is the CFS bandwidth cap (cpu.max) actually throttling
# on this cluster? Deploy the SAME single-threaded burst at three cpu limits; if
# enforced, a lower limit makes the fixed burst proportionally slower. If all
# three are equal, cpu.max is set in the cgroup but not throttling — which is the
# premise of F-2's CPU result.
ENF="iso-enforce"
enforce() {
  local work="${CPU_WORK:-200000000}"
  echo "── CPU follow-on: is cpu.max enforced on this cluster? ──"
  echo "deploying identical single-burst workers at cpu limits 200m / 500m / 2000m…"
  local dir; dir="$(mktemp -d)"
  emit_worker "$ENF-200m" 1 200m  > "$dir/e1.yaml"
  emit_worker "$ENF-500m" 1 500m  > "$dir/e2.yaml"
  emit_worker "$ENF-2000m" 1 2000m > "$dir/e3.yaml"
  kubectl apply -f "$dir" >/dev/null
  for l in 200m 500m 2000m; do
    kubectl -n "$NS" rollout status "deploy/$ENF-$l" --timeout=120s >/dev/null
  done
  sleep 2
  echo "fixed $work-iter burst wall time per limit (enforced ⇒ lower limit = slower):"
  for l in 200m 500m 2000m; do
    local cpumax; cpumax=$(kubectl -n "$NS" exec "deploy/$ENF-$l" -c workerd -- cat /sys/fs/cgroup/cpu.max 2>/dev/null)
    local s1 s2 s3
    s1=$(hit "$ENF-$l" 8080 "role=victim&work=$work" | grep -o '"work_ms":[0-9]*' | grep -o '[0-9]*$')
    s2=$(hit "$ENF-$l" 8080 "role=victim&work=$work" | grep -o '"work_ms":[0-9]*' | grep -o '[0-9]*$')
    s3=$(hit "$ENF-$l" 8080 "role=victim&work=$work" | grep -o '"work_ms":[0-9]*' | grep -o '[0-9]*$')
    printf "  limit=%-6s cpu.max=[%s]  burst_ms=%s,%s,%s\n" "$l" "$cpumax" "$s1" "$s2" "$s3"
  done
  echo "down with: $0 enforce-down"
}

enforce_down() {
  kubectl -n "$NS" delete sandboxworker "$ENF-200m" "$ENF-500m" "$ENF-2000m" --ignore-not-found
}

run_cpu() {
  local W="${CPU_WORK:-200000000}"
  local cb="http://$COLO.$NS.svc.cluster.local"
  echo "── (d) P-WL-ISO-002 CPU shared-fate ──"
  echo "(two identical bursts fired concurrently; overlap≈0 ⇒ serialized on a"
  echo " shared execution thread = CPU shared fate; overlap≈burst ⇒ true parallel)"
  cpu_report "COLO (isolate-0 + isolate-1, one pod):" \
    $(cpu_pair "$cb:8080/?role=victim&work=$W" "$cb:8081/?role=victim&work=$W")
  cpu_report "SEP (sep-a + sep-v, two pods):" \
    $(cpu_pair "http://$SEP_A.$NS.svc.cluster.local:8080/?role=victim&work=$W" \
               "http://$SEP_V.$NS.svc.cluster.local:8080/?role=victim&work=$W")
}

# ── (d) socket/fd flood (exploratory) ───────────────────────────────────────

run_fd() {
  local sink="${1:-}"
  echo "── (d) P-WL-ISO-002 socket/fd flood (exploratory) ──"
  if [ -z "$sink" ]; then
    echo "usage: $0 fd <hang-sink-url>  (needs egress; under deny-all-egress this won't load)"
    return 1
  fi
  echo "COLO baseline victim latency (isolate-1): $(victim_latency "$COLO" 8081) ms"
  echo "firing 256-socket flood at COLO isolate-0 in background…"
  hit "$COLO" 8080 "role=aggressor&resource=fd&n=256&ms=8000&sink=$sink" >/dev/null &
  local agg=$!
  sleep 2
  echo "COLO victim latency on isolate-1 DURING flood: $(victim_latency "$COLO" 8081) ms"
  wait "$agg" 2>/dev/null
}

# ── entrypoint ──────────────────────────────────────────────────────────────

cmd="${1:-}"
case "$cmd" in
  render) render "${2:-}";;
  up)     up;;
  down)   down;;
  cache)  run_cache;;
  mem)    run_mem;;
  cpu)    run_cpu;;
  fd)     run_fd "${2:-}";;
  enforce)      enforce;;
  enforce-down) enforce_down;;
  all)    run_cache; echo; run_mem; echo; run_cpu;;
  *)      sed -n '2,28p' "$0"; exit 1;;
esac
