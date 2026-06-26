#!/usr/bin/env bash
set -euo pipefail

RUN_ID="${RUN_ID:-talos-poc-$(date +%s)}"
PORT="${PORT:-18081}"
EGRESS_TARGET="${EGRESS_TARGET:-http://93.184.216.34/}"
OUT_DIR="${OUT_DIR:-wulf-operator/out/$RUN_ID}"
NAMESPACE="${NAMESPACE:-wulf-system}"

mkdir -p "$OUT_DIR"

pod="$(kubectl -n "$NAMESPACE" get pod -l app.kubernetes.io/name=workerd-rt-001 -o jsonpath='{.items[0].metadata.name}')"
node="$(kubectl -n "$NAMESPACE" get pod "$pod" -o jsonpath='{.spec.nodeName}')"
tetragon_pod="$(kubectl -n kube-system get pod -l app.kubernetes.io/name=tetragon --field-selector "spec.nodeName=$node" -o jsonpath='{.items[0].metadata.name}')"

kubectl -n "$NAMESPACE" port-forward svc/workerd-rt-001 "$PORT:8080" >/tmp/wulf-operator-port-forward.log 2>&1 &
pf_pid="$!"
trap 'kill "$pf_pid" >/dev/null 2>&1 || true' EXIT

for _ in $(seq 1 40); do
  if curl -fsS "http://127.0.0.1:$PORT/?run_id=$RUN_ID" >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

since="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
curl -fsS "http://127.0.0.1:$PORT/?run_id=$RUN_ID&egress_target=$(node -e 'process.stdout.write(encodeURIComponent(process.argv[1]))' "$EGRESS_TARGET")" \
  > "$OUT_DIR/probe-result.json"

kubectl -n kube-system exec "$tetragon_pod" -c tetragon -- \
  tail -5000 /var/run/cilium/tetragon/tetragon.log \
  > "$OUT_DIR/tetragon.log"

node wulf-operator/scripts/collect-observation.mjs \
  --probe-result "$OUT_DIR/probe-result.json" \
  --tetragon-log "$OUT_DIR/tetragon.log" \
  --pod-name "$pod" \
  --node-name "$node" \
  --since "$since" \
  --output "$OUT_DIR/observation.jsonl"

echo "$OUT_DIR/observation.jsonl"
