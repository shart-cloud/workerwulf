// A stand-in for api.cloudflare.com/client/v4, bound to the hub as CF_API in tests.
// Tests set the account with `POST /__state` and change it between scans.
//
// State: {
//   scripts: { [name]: { bindings?, routes?, content?, fail?: { settings?, routes?, content?: status } } },
//   namespaces: { [name]: <namespace API object> },
//   fail: { list?: status, namespaces?: status },
// }
let state = { scripts: {}, namespaces: {}, fail: {} };
let requests = 0;

const ok = (result) => Response.json({ success: true, errors: [], result });
const status = (code) => Response.json({ success: false, errors: [{ message: `HTTP ${code}` }] }, { status: code });

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/__state") {
      if (request.method === "POST") {
        state = { scripts: {}, namespaces: {}, fail: {}, ...(await request.json()) };
        requests = 0;
        return new Response("ok");
      }
      return Response.json({ requests });
    }
    requests++;
    if (request.headers.get("authorization") !== "Bearer cf-test-token") return status(401);

    const m = url.pathname.match(/^\/client\/v4\/accounts\/[^/]+\/workers\/(.*)$/);
    if (!m) return status(404);
    const rest = m[1].split("/").map(decodeURIComponent);

    if (rest[0] === "scripts" && rest.length === 1) {
      if (state.fail.list) return status(state.fail.list);
      return ok(Object.keys(state.scripts).map((id) => ({ id })));
    }
    if (rest[0] === "scripts" && rest.length === 3) {
      const script = state.scripts[rest[1]];
      if (!script) return status(404);
      const op = rest[2];
      if (script.fail?.[op]) return status(script.fail[op]);
      if (op === "settings") return ok({ bindings: script.bindings ?? [] });
      if (op === "routes") return ok((script.routes ?? []).map((pattern) => ({ pattern })));
      if (op === "content") {
        return new Response(script.content ?? "", { headers: { "content-type": "application/javascript" } });
      }
      return status(404);
    }
    if (rest[0] === "dispatch" && rest[1] === "namespaces") {
      if (state.fail.namespaces) return status(state.fail.namespaces);
      if (rest.length === 2) return ok(Object.keys(state.namespaces).map((namespace_name) => ({ namespace_name })));
      const ns = state.namespaces[rest[2]];
      return ns ? ok(ns) : status(404);
    }
    return status(404);
  },
};
