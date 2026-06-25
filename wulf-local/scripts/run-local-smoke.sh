#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORKERD="${WORKERD:-$ROOT/node_modules/.pnpm/node_modules/.bin/workerd}"
IMPORT_DIR="${IMPORT_DIR:-$ROOT/node_modules/.pnpm/workerd@1.20260521.1/node_modules}"
CONFIG="$ROOT/wulf-local/config/workerd.poc.capnp"
PORT="${PORT:-18080}"
RUN_ID="${RUN_ID:-local-smoke}"
EGRESS_TARGET="${EGRESS_TARGET:-}"
LOG_FILE="/tmp/wulf-local-workerd-$PORT.log"
RESULT_FILE="/tmp/wulf-local-probe-$PORT.json"

if [[ ! -x "$WORKERD" ]]; then
  echo "workerd binary not found at $WORKERD" >&2
  exit 2
fi

"$WORKERD" serve "$CONFIG" -I "$IMPORT_DIR" --socket-addr "http=127.0.0.1:$PORT" >"$LOG_FILE" 2>&1 &
pid="$!"
trap 'kill "$pid" >/dev/null 2>&1 || true' EXIT

ready=0
for _ in $(seq 1 40); do
  if ! kill -0 "$pid" >/dev/null 2>&1; then
    cat "$LOG_FILE" >&2
    exit 1
  fi
  if curl -fsS "http://127.0.0.1:$PORT/?run_id=$RUN_ID" >"$RESULT_FILE" 2>/dev/null; then
    ready=1
    break
  fi
  sleep 0.25
done

if [[ "$ready" != "1" ]]; then
  cat "$LOG_FILE" >&2
  exit 1
fi

query="run_id=$RUN_ID"
if [[ -n "$EGRESS_TARGET" ]]; then
  query="$query&egress_target=$(node -e 'process.stdout.write(encodeURIComponent(process.argv[1]))' "$EGRESS_TARGET")"
fi

curl -fsS "http://127.0.0.1:$PORT/?$query" >"$RESULT_FILE"

export RESULT_FILE
node - <<'NODE'
const fs = require("node:fs");
const result = JSON.parse(fs.readFileSync(process.env.RESULT_FILE, "utf8"));
const required = ["test_id", "track", "timestamp", "description", "result", "severity", "details"];
for (const key of required) {
  if (!(key in result)) throw new Error(`missing ${key}`);
}
if (result.test_id !== "P-WL-RT-001") throw new Error(`unexpected test_id ${result.test_id}`);
if (result.track !== "platform") throw new Error(`unexpected track ${result.track}`);
if (result.details.platform !== "wulf-local") throw new Error("details.platform must be wulf-local");
if (result.details.local_track !== "runtime-fingerprint") throw new Error("details.local_track must be runtime-fingerprint");
process.stdout.write(JSON.stringify(result, null, 2));
process.stdout.write("\n");
NODE
