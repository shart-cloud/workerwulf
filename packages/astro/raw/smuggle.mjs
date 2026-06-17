// A-BODY-* — raw-socket HTTP/1.1 framing / request-smuggling driver.
//
// fetch()/Request forbid duplicate Content-Length, Transfer-Encoding, and
// malformed chunking, so these desync tests need raw TCP. This is a Node tool
// (workerd has no raw sockets) — it is NOT a probe-worker probe. It connects to
// the Astro target, sends crafted byte streams, and reports how the front HTTP
// parser (workerd, when served via `astro preview`) frames them.
//
//   node raw/smuggle.mjs [--target 127.0.0.1:8788] [--json]
//
// A secure parser rejects ambiguous framing (400/501) and never emits two
// responses to one socket write (which would indicate smuggling/desync).
import net from "node:net";
import { parseArgs } from "node:util";

const { values } = parseArgs({
  options: { target: { type: "string", default: "127.0.0.1:8788" }, json: { type: "boolean", default: false } },
});
const [HOST, PORT] = values.target.split(":");
const CRLF = "\r\n";

function sendRaw(payload, { timeout = 4000 } = {}) {
  return new Promise((resolve) => {
    const sock = net.connect(Number(PORT), HOST);
    let data = "";
    const done = (outcome) => {
      try { sock.destroy(); } catch {}
      resolve({ ...outcome, raw: data });
    };
    sock.setTimeout(timeout, () => done({ outcome: "timeout" }));
    sock.on("connect", () => sock.write(payload));
    sock.on("data", (b) => { data += b.toString("latin1"); });
    sock.on("end", () => done({ outcome: "closed" }));
    sock.on("error", (e) => done({ outcome: "error", error: e.code || e.message }));
  });
}

/** Count HTTP response status lines (≥2 ⇒ the socket produced multiple responses ⇒ desync). */
function statusLines(raw) {
  const m = [...raw.matchAll(/HTTP\/1\.[01] (\d{3})/g)].map((x) => Number(x[1]));
  return m;
}

const ORIGIN = `http://${HOST}:${PORT}`;
const body = `{"message":"x"}`;

// Each case: a raw byte string. Header order/whitespace is deliberate.
const cases = [
  {
    id: "A-BODY-00",
    name: "baseline-valid-post",
    desc: "well-formed POST — sanity",
    payload:
      `POST /_actions/echo HTTP/1.1${CRLF}Host: ${HOST}${CRLF}Origin: ${ORIGIN}${CRLF}` +
      `Content-Type: application/json${CRLF}Content-Length: ${body.length}${CRLF}Connection: close${CRLF}${CRLF}${body}`,
    secure: (s) => s.length === 1, // exactly one response
  },
  {
    id: "A-BODY-01",
    name: "duplicate-content-length",
    desc: "two conflicting Content-Length headers",
    payload:
      `POST /a HTTP/1.1${CRLF}Host: ${HOST}${CRLF}Content-Length: 6${CRLF}Content-Length: 5${CRLF}` +
      `Content-Type: text/plain${CRLF}Connection: close${CRLF}${CRLF}AAAAAA`,
    secure: (s) => s[0] === 400 || s.length === 0, // rejected
  },
  {
    id: "A-BODY-02",
    name: "cl-te-desync",
    desc: "Content-Length + Transfer-Encoding: chunked (CL.TE)",
    payload:
      `POST /a HTTP/1.1${CRLF}Host: ${HOST}${CRLF}Content-Length: 4${CRLF}` +
      `Transfer-Encoding: chunked${CRLF}Connection: close${CRLF}${CRLF}` +
      `0${CRLF}${CRLF}GET /a HTTP/1.1${CRLF}Host: ${HOST}${CRLF}${CRLF}`,
    secure: (s) => s.length <= 1 && (s.length === 0 || s[0] === 400), // no 2nd (smuggled) response
  },
  {
    id: "A-BODY-03",
    name: "te-obfuscation-space",
    desc: "obfuscated header name `Transfer-Encoding : chunked` (space before colon)",
    payload:
      `POST /a HTTP/1.1${CRLF}Host: ${HOST}${CRLF}Content-Length: 6${CRLF}` +
      `Transfer-Encoding : chunked${CRLF}Connection: close${CRLF}${CRLF}AAAAAA`,
    secure: (s) => s.length <= 1, // not treated as a smuggling split
  },
  {
    id: "A-BODY-04",
    name: "malformed-chunk-size",
    desc: "Transfer-Encoding: chunked with a non-hex chunk size",
    payload:
      `POST /a HTTP/1.1${CRLF}Host: ${HOST}${CRLF}Transfer-Encoding: chunked${CRLF}` +
      `Connection: close${CRLF}${CRLF}ZZ${CRLF}AAAA${CRLF}0${CRLF}${CRLF}`,
    secure: (s) => s[0] === 400 || s.length === 0, // rejected
  },
];

const results = [];
for (const c of cases) {
  const r = await sendRaw(c.payload);
  const s = statusLines(r.raw);
  const secure = c.secure(s);
  results.push({
    test_id: c.id,
    track: "astro",
    name: c.name,
    description: c.desc,
    result: secure ? "blocked" : "accessible",
    severity: secure ? "informational" : "high",
    details: {
      status_lines: s,
      response_count: s.length,
      outcome: r.outcome,
      first_120: r.raw.slice(0, 120).replace(/\r/g, "\\r").replace(/\n/g, "\\n"),
    },
  });
}

if (values.json) {
  console.log(JSON.stringify(results, null, 2));
} else {
  for (const r of results) {
    const verdict = r.result === "blocked" ? "OK  " : "FLAG";
    console.log(
      `[${verdict}] ${r.test_id} ${r.name.padEnd(26)} status=${JSON.stringify(r.details.status_lines)} responses=${r.details.response_count} (${r.details.outcome})`,
    );
  }
  const flagged = results.filter((r) => r.result === "accessible");
  console.log(`\n${results.length} cases, ${flagged.length} flagged.`);
}
