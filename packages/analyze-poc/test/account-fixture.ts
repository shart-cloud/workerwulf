import { NotFound, PermissionDenied, type PromiseCfClient, type RawBinding, type RawNamespace } from "@wulf/core";

/**
 * A canned account that triggers every account rule and records two coverage
 * gaps:
 * - `prey`: an unused KV binding (WF-PRIV-01), Hyperdrive on a public route
 *   (WF-PRIV-02), and deployed code that differs from the local source in the
 *   CLI's `deployed-local` fixture (WF-DRIFT-01);
 * - `locked`: its bindings read is denied and its routes endpoint is missing;
 * - `tenants`: a trusted dispatch namespace with no outbound Worker or limits,
 *   holding a script not marked untrusted (WF-NS-01..04).
 */
export class FixtureAccount implements PromiseCfClient {
  async listScripts(): Promise<string[]> {
    return ["prey", "locked"];
  }
  async getScriptBindings(name: string): Promise<RawBinding[]> {
    if (name === "locked") {
      throw new PermissionDenied({ path: "/accounts/acct/workers/scripts/locked/settings", status: 403 });
    }
    return [
      { type: "hyperdrive", name: "HYPERDRIVE", id: "hd1" },
      { type: "kv_namespace", name: "UNUSED_KV", namespace_id: "kv1" },
      { type: "secret_text", name: "API_TOKEN" },
      { type: "plain_text", name: "GREETING", text: "hi" },
    ];
  }
  async getScriptContent(name: string): Promise<string | undefined> {
    return name === "prey"
      ? "export default { fetch(req, env) { return new Response(env.HYPERDRIVE.connectionString + env.API_TOKEN); } };"
      : "export default { fetch() { return new Response('ok'); } };";
  }
  async getRoutes(name: string): Promise<string[]> {
    if (name === "locked") throw new NotFound({ path: "/accounts/acct/workers/scripts/locked/routes" });
    return ["prey.example.com/*"];
  }
  async listNamespaces(): Promise<string[]> {
    return ["tenants"];
  }
  async getNamespace(name: string): Promise<RawNamespace | undefined> {
    return { name, trusted: true, scripts: [{ name: "tenant-a", untrusted: false }] };
  }
}
