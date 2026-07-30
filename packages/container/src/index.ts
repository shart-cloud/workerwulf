import { DurableObject, WorkerEntrypoint } from "cloudflare:workers";

/**
 * Wave 6 — the deliberately-vulnerable target for the Cloudflare Containers
 * `exec()` probe family (W-CTR-01…11). See docs/wave6-containers-exec.md.
 *
 * `CtrTarget` is a Durable Object with a container attached. It exposes a thin
 * JSON-RPC surface over `this.ctx.container` so that a probe running inside
 * `wulf-worker` can drive real process execution: caller-chosen argv, caller-chosen
 * `sh -c` strings, caller-chosen env/user/cwd, and — the shape this wave exists for —
 * an HTTP request body streamed straight into a process's stdin.
 *
 * It is vulnerable ON PURPOSE, exactly like the Wave 5 `WcVictim` entrypoint. The
 * point is to demonstrate the sinks rather than assert about them. What keeps that
 * safe is the rail set, not the absence of the sinks:
 *
 *   - every exec is wrapped in a hard timeout + `kill()` in a `finally`, so no probe
 *     can leave a runaway process behind (W-CTR-06 deliberately observes lifetime,
 *     and cleans up on the way out);
 *   - stdout/stderr are capped before they cross back into the isolate, except in
 *     W-CTR-08 which ramps a bounded volume on purpose;
 *   - egress targets come from the probe and the probes only ever name the
 *     researcher's own callback host, loopback, or documented-reserved ranges;
 *   - nothing is written outside /tmp and /srv.
 *
 * The `experimental` @cloudflare/workers-types entry is required for these APIs —
 * the default entry's `Container` interface has no `exec()`.
 */

export interface Env {
  CTR_TARGET: DurableObjectNamespace<CtrTarget>;
  // W-CTR-10: where interceptOutbound*() reroutes container egress.
  INTERCEPT_SINK: Fetcher;
  // W-CTR-04 canaries. The secret is set out of band via `wrangler secret put`.
  WULF_CTR_VAR?: string;
  WULF_CTR_SECRET?: string;
  // Shared secret gating the whole RPC surface. Set on BOTH wulf-container and
  // wulf-worker via `wrangler secret put WULF_CTR_AUTH`. See `authorized()`.
  WULF_CTR_AUTH?: string;
}

/**
 * This Worker is a deliberately-vulnerable exec surface: `POST /ctr/exec_shell` runs an
 * arbitrary `sh -c` string inside the container. `workers_dev = false` keeps it off the
 * public internet, but that is a routing setting — a stale route, a preview URL or a
 * future config slip would expose remote code execution to anyone who found the
 * hostname. The shared-secret gate is the control that does not depend on routing.
 *
 * Constant-time compare so the gate itself is not a timing oracle.
 */
function authorized(req: Request, env: Env): boolean {
  const expected = env.WULF_CTR_AUTH;
  if (!expected) return false; // fail closed: no secret configured, no access
  const presented = req.headers.get("x-wulf-ctr-auth") ?? "";
  if (presented.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= presented.charCodeAt(i) ^ expected.charCodeAt(i);
  return diff === 0;
}

/** Cap on text handed back to the isolate, per stream. */
const OUTPUT_CAP = 4000;
/** Default wall-clock ceiling on any single exec. */
const EXEC_TIMEOUT_MS = 20_000;
/** Cap on a stdin payload accepted from a caller (W-CTR-03 measures up to this). */
const STDIN_CAP_BYTES = 8 * 1024 * 1024;

interface ExecRecord {
  ok: boolean;
  cmd: string[];
  pid: number | null;
  exit_code: number | null;
  stdout: string;
  stderr: string;
  stdout_bytes: number;
  stderr_bytes: number;
  truncated: boolean;
  timed_out: boolean;
  duration_ms: number;
  error?: string;
}

function decodeCapped(buf: ArrayBuffer): { text: string; bytes: number; truncated: boolean } {
  const bytes = buf.byteLength;
  const slice = bytes > OUTPUT_CAP ? buf.slice(0, OUTPUT_CAP) : buf;
  return {
    text: new TextDecoder().decode(slice),
    bytes,
    truncated: bytes > OUTPUT_CAP,
  };
}

async function sha256Hex(buf: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function hexPrefix(buf: ArrayBuffer, n = 16): string {
  return [...new Uint8Array(buf.slice(0, n))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

export class CtrTarget extends DurableObject<Env> {
  /** Startup options the container is currently running under (null = never started). */
  private startedWith: ContainerStartupOptions | null = null;

  /**
   * `destroy()` can hang indefinitely — observed live in the first Wave 6 run: a
   * destroy/restart wedged the object, and because requests to one Durable Object are
   * serialized, every later probe queued behind it and timed out. Racing it keeps a
   * stuck teardown to one failed op instead of an unusable instance.
   */
  private async destroyBounded(timeoutMs = 20_000): Promise<string | null> {
    try {
      const timed = new Promise<"timeout">((r) => setTimeout(() => r("timeout"), timeoutMs));
      const res = await Promise.race([this.container.destroy().then(() => "ok" as const), timed]);
      return res === "timeout" ? `destroy() did not settle within ${timeoutMs}ms` : null;
    } catch (err) {
      return err instanceof Error ? err.message : String(err);
    }
  }

  private get container(): Container {
    const c = this.ctx.container;
    if (!c) {
      throw new Error("no container attached to this Durable Object (wrangler [[containers]] missing?)");
    }
    return c;
  }

  /**
   * `exec()` does not start a stopped container, so every op goes through here. The
   * container's own readiness is not instantaneous after `start()` returns, hence the
   * bounded retry.
   */
  private async ensureRunning(options?: ContainerStartupOptions): Promise<void> {
    const c = this.container;
    if (c.running) return;
    const opts: ContainerStartupOptions = options ?? {
      enableInternet: true,
      env: {
        WULF_CTR_VAR: this.env.WULF_CTR_VAR ?? "",
        WULF_CTR_SECRET: this.env.WULF_CTR_SECRET ?? "",
        WULF_CTR_START: "container-envvars",
      },
    };
    c.start(opts);
    this.startedWith = opts;
    for (let i = 0; i < 40 && !c.running; i++) {
      await new Promise((r) => setTimeout(r, 250));
    }
  }

  /** Run one process to completion under a hard timeout, capping what comes back. */
  private async runExec(
    cmd: string[],
    options: ContainerExecOptions = {},
    timeoutMs = EXEC_TIMEOUT_MS,
  ): Promise<ExecRecord> {
    const started = Date.now();
    const record: ExecRecord = {
      ok: false,
      cmd,
      pid: null,
      exit_code: null,
      stdout: "",
      stderr: "",
      stdout_bytes: 0,
      stderr_bytes: 0,
      truncated: false,
      timed_out: false,
      duration_ms: 0,
    };

    let proc: ExecProcess | null = null;
    let timedOut = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    try {
      proc = await this.container.exec(cmd, { stdout: "pipe", stderr: "pipe", ...options });
      record.pid = proc.pid;
      const handle = proc;
      timer = setTimeout(() => {
        timedOut = true;
        try {
          handle.kill(9);
        } catch {
          /* already gone */
        }
      }, timeoutMs);

      const out = await handle.output();
      const so = decodeCapped(out.stdout);
      const se = decodeCapped(out.stderr);
      record.exit_code = out.exitCode;
      record.stdout = so.text;
      record.stderr = se.text;
      record.stdout_bytes = so.bytes;
      record.stderr_bytes = se.bytes;
      record.truncated = so.truncated || se.truncated;
      record.ok = out.exitCode === 0;
    } catch (err) {
      record.error = err instanceof Error ? err.message : String(err);
    } finally {
      if (timer !== null) clearTimeout(timer);
      // Rail: never leave a process behind, whatever happened above.
      try {
        proc?.kill();
      } catch {
        /* already exited */
      }
      record.timed_out = timedOut;
      record.duration_ms = Date.now() - started;
    }
    return record;
  }

  /** Convenience: run `sh -c` with a caller-supplied string. The injection sink. */
  private shell(command: string, options: ContainerExecOptions = {}, timeoutMs?: number) {
    return this.runExec(["sh", "-c", command], options, timeoutMs);
  }

  override async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const op = url.pathname.replace(/^\/ctr\//, "");

    try {
      // The one op that needs the raw request stream rather than a JSON payload:
      // W-CTR-03 streams the caller's body directly into the process's stdin.
      if (op === "stdin") return await this.opStdin(req, url);

      const payload = req.method === "POST" ? ((await req.json()) as Record<string, unknown>) : {};
      const handler = this.ops[op];
      if (!handler) return json({ error: "unknown_op", op }, 404);
      return json(await handler(payload));
    } catch (err) {
      return json({ error: err instanceof Error ? err.message : String(err), op }, 500);
    }
  }

  private ops: Record<string, (p: Record<string, unknown>) => Promise<unknown>> = {
    /** W-CTR-01 — what the container gives an attacker who reaches exec(). */
    introspect: async () => {
      await this.ensureRunning();
      const c = this.container;
      let info: ContainerInfo | null = null;
      let inspectError: string | null = null;
      try {
        info = await c.inspect();
      } catch (err) {
        inspectError = err instanceof Error ? err.message : String(err);
      }
      const [id, status, cgroup, mounts, tools, netns] = await Promise.all([
        this.runExec(["id"]),
        this.shell("grep -E '^(Uid|Gid|CapEff|CapBnd|Seccomp|NoNewPrivs)' /proc/self/status"),
        this.shell(
          "cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/cpu.max 2>/dev/null; nproc; cat /proc/meminfo | head -3",
        ),
        this.shell("cat /proc/mounts"),
        this.shell("for t in ffmpeg curl busybox ip ps nc python3 perl gcc; do command -v $t || echo \"absent:$t\"; done"),
        this.shell("ip -o addr 2>/dev/null; ip route 2>/dev/null; cat /etc/resolv.conf 2>/dev/null"),
      ]);
      return {
        container_running: c.running,
        exec_present: typeof c.exec === "function",
        api_surface: {
          exec: typeof c.exec,
          inspect: typeof c.inspect,
          get_tcp_port: typeof c.getTcpPort,
          snapshot_directory: typeof c.snapshotDirectory,
          snapshot_container: typeof c.snapshotContainer,
          intercept_outbound_http: typeof c.interceptOutboundHttp,
          intercept_outbound_https: typeof c.interceptOutboundHttps,
          intercept_outbound_tcp: typeof c.interceptOutboundTcp,
          intercept_all_outbound_http: typeof c.interceptAllOutboundHttp,
          set_inactivity_timeout: typeof c.setInactivityTimeout,
          destroy: typeof c.destroy,
          signal: typeof c.signal,
        },
        inspect: info,
        inspect_error: inspectError,
        id,
        proc_status: status,
        limits: cgroup,
        mounts,
        tools,
        network: netns,
        started_with: this.startedWith,
      };
    },

    /** W-CTR-02 / W-CTR-07 — argv passthrough, with caller-controlled exec options. */
    exec_argv: async (p) => {
      await this.ensureRunning();
      const cmd = Array.isArray(p.cmd) ? (p.cmd as string[]) : ["echo", "no-cmd"];
      const options: ContainerExecOptions = {};
      if (p.env && typeof p.env === "object") options.env = p.env as Record<string, string>;
      if (typeof p.cwd === "string") options.cwd = p.cwd;
      if (typeof p.user === "string") options.user = p.user;
      if (p.stderr === "combined") options.stderr = "combined";
      if (p.stdout === "ignore") options.stdout = "ignore";
      return this.runExec(cmd, options, typeof p.timeout_ms === "number" ? p.timeout_ms : undefined);
    },

    /** W-CTR-02 — the same untrusted string, interpolated into a shell. The sink. */
    exec_shell: async (p) => {
      await this.ensureRunning();
      const command = typeof p.command === "string" ? p.command : "true";
      const options: ContainerExecOptions = {};
      if (p.env && typeof p.env === "object") options.env = p.env as Record<string, string>;
      if (typeof p.cwd === "string") options.cwd = p.cwd;
      if (typeof p.user === "string") options.user = p.user;
      return this.shell(command, options, typeof p.timeout_ms === "number" ? p.timeout_ms : undefined);
    },

    /** W-CTR-06 — spawn a process, return WITHOUT awaiting it, report the pid. */
    spawn_detached: async (p) => {
      await this.ensureRunning();
      const seconds = Math.min(Number(p.seconds ?? 90), 300);
      const marker = typeof p.marker === "string" ? p.marker.replace(/[^\w-]/g, "") : "wulf-detached";
      // The process needs a name `ps`/`pkill -f` can match. `exec -a` is a bashism, and
      // copying /bin/sleep breaks on busybox-based images, so keep a shell alive in a
      // sleep loop instead: the marker stays visible in the shell's own argv.
      const proc = await this.container.exec([
        "sh",
        "-c",
        `i=0; while [ $i -lt ${seconds} ]; do sleep 1; i=$((i+1)); done # ${marker}`,
      ]);
      // Deliberately NOT awaited and NOT killed — the whole question is whether it
      // outlives this request. W-CTR-06 reaps it explicitly via the `kill_marker` op.
      return { pid: proc.pid, marker, seconds, spawned_at: new Date().toISOString() };
    },

    /** W-CTR-06 — is a previously-spawned marker still in the process table? */
    ps: async (p) => {
      await this.ensureRunning();
      const pattern = typeof p.pattern === "string" ? p.pattern : "sleep";
      const table = await this.shell("ps -eo pid,ppid,etimes,stat,comm,args --no-headers");
      const matches = (table.stdout.match(new RegExp(pattern.replace(/[^\w-]/g, ""), "g")) ?? []).length;
      return { table, pattern, match_count: matches, container_running: this.container.running };
    },

    /**
     * W-CTR-06 cleanup rail — reap the process the lifetime probe spawned.
     *
     * By pid, not by marker: `pkill -f <marker>` matches the killing shell's *own*
     * command line (the marker is in its argv), so it kills itself before reaping the
     * target. Observed live — the first run reported an unreaped process for exactly
     * this reason. The probe already holds the pid from `spawn_detached`.
     */
    kill_pid: async (p) => {
      await this.ensureRunning();
      const pid = Math.trunc(Number(p.pid ?? 0));
      if (!Number.isFinite(pid) || pid <= 1) return { killed: false, error: "refusing to signal pid <= 1", pid };
      const rec = await this.shell(
        `kill -9 ${pid} 2>/dev/null; sleep 0.5; kill -0 ${pid} 2>/dev/null && echo alive || echo reaped`,
      );
      return { killed: rec.stdout.includes("reaped"), pid, exec: rec };
    },

    /** W-CTR-04 — does Worker config reach the process, and can the caller override it? */
    env_probe: async (p) => {
      await this.ensureRunning();
      const override =
        p.env && typeof p.env === "object" ? (p.env as Record<string, string>) : undefined;
      const [inherited, overridden, pid1, envFiles] = await Promise.all([
        this.shell("env | sort"),
        override ? this.shell("env | sort", { env: override }) : Promise.resolve(null),
        this.shell("tr '\\0' '\\n' < /proc/1/environ 2>&1 | sort"),
        this.shell("cat /proc/self/environ 2>&1 | tr '\\0' '\\n' | wc -l; ls -la /proc/1/ 2>&1 | head -5"),
      ]);
      return {
        worker_var_present_in_worker: Boolean(this.env.WULF_CTR_VAR),
        worker_secret_present_in_worker: Boolean(this.env.WULF_CTR_SECRET),
        inherited,
        overridden,
        pid1_environ: pid1,
        proc_access: envFiles,
      };
    },

    /**
     * W-CTR-05 — where can a container process reach that the isolate cannot?
     * Targets are supplied by the probe; the probe only ever names the researcher's
     * own callback host, loopback, or reserved ranges.
     */
    egress: async (p) => {
      await this.ensureRunning();
      const targets = Array.isArray(p.targets) ? (p.targets as Array<Record<string, unknown>>) : [];
      const results: Record<string, unknown>[] = [];
      for (const t of targets.slice(0, 12)) {
        const label = String(t.label ?? "unlabelled");
        const kind = String(t.kind ?? "http");
        const target = String(t.target ?? "");
        let rec: ExecRecord;
        if (kind === "tcp") {
          const port = Number(t.port ?? 80);
          // Connect test only — busybox's nc has no `-z` and dash has no /dev/tcp, so
          // curl reports the handshake instead: `%{time_connect}` is non-zero if and
          // only if the TCP connection was established, whatever happens afterwards
          // (a non-HTTP service such as sshd errors out *after* connecting).
          rec = await this.shell(
            `out=$(curl -sS -m 5 --connect-timeout 4 -o /dev/null ` +
              `-w 'connect=%{time_connect} ip=%{remote_ip}' http://${target}:${port}/ 2>&1); rc=$?; ` +
              `echo "$out rc=$rc"; ` +
              // Match anywhere in $out, not just at the start: curl prints its own
              // error line first when the service is not HTTP (an sshd banner gives
              // "Received HTTP/0.9 when not allowed") — a connect that plainly
              // succeeded. Anchoring on the prefix reported those as UNKNOWN.
              `case "$out" in *connect=0.000000*) echo CLOSED ;; *connect=*) echo OPEN ;; *) echo UNKNOWN ;; esac`,
            {},
            9000,
          );
        } else if (kind === "dns") {
          rec = await this.shell(`getent hosts ${JSON.stringify(target)} || echo NXDOMAIN`, {}, 8000);
        } else {
          rec = await this.shell(
            `curl -sS -m 5 -o /dev/null -w '%{http_code} %{remote_ip} %{time_total}' ${JSON.stringify(target)}`,
            {},
            10_000,
          );
        }
        results.push({ label, kind, target, port: t.port ?? null, exec: rec });
      }
      return { results, started_with: this.startedWith, container_running: this.container.running };
    },

    /**
     * W-CTR-05 — restart under caller-chosen ContainerStartupOptions (notably
     * `enableInternet: false`) to test whether the network policy binds exec'd
     * processes or only the image entrypoint.
     */
    restart: async (p) => {
      const c = this.container;
      const destroyError = await this.destroyBounded();
      const opts: ContainerStartupOptions = {
        enableInternet: p.enable_internet !== false,
      };
      if (p.env && typeof p.env === "object") opts.env = p.env as Record<string, string>;
      if (Array.isArray(p.entrypoint)) opts.entrypoint = p.entrypoint as string[];
      if (typeof p.hard_timeout === "number") opts.hardTimeout = p.hard_timeout;
      if (typeof p.labels === "object" && p.labels) opts.labels = p.labels as Record<string, string>;
      await this.ensureRunning(opts);
      return { restarted: true, destroy_error: destroyError, started_with: opts, running: c.running };
    },

    /** W-CTR-08 — buffer N bytes of stdout back through output() into the isolate. */
    big_output: async (p) => {
      await this.ensureRunning();
      const bytes = Math.min(Number(p.bytes ?? 1_000_000), 512 * 1024 * 1024);
      const started = Date.now();
      let proc: ExecProcess | null = null;
      try {
        proc = await this.container.exec(["head", "-c", String(bytes), "/dev/zero"], {
          stdout: "pipe",
          stderr: "ignore",
        });
        const out = await proc.output();
        return {
          ok: true,
          requested_bytes: bytes,
          received_bytes: out.stdout.byteLength,
          exit_code: out.exitCode,
          duration_ms: Date.now() - started,
        };
      } catch (err) {
        return {
          ok: false,
          requested_bytes: bytes,
          error: err instanceof Error ? err.message : String(err),
          duration_ms: Date.now() - started,
        };
      } finally {
        try {
          proc?.kill();
        } catch {
          /* gone */
        }
      }
    },

    /** W-CTR-09 — write a runtime marker, snapshot, and report the handle. */
    snapshot: async (p) => {
      await this.ensureRunning();
      const dir = typeof p.dir === "string" ? p.dir : "/tmp/wulf";
      const marker = typeof p.marker === "string" ? p.marker : "flag{w-ctr-09-runtime}";
      const name = typeof p.name === "string" ? p.name : "wulf-ctr-09";
      const write = await this.shell(
        `mkdir -p ${JSON.stringify(dir)} && printf %s ${JSON.stringify(marker)} > ${JSON.stringify(`${dir}/marker.txt`)} && cat ${JSON.stringify(`${dir}/marker.txt`)}`,
      );
      const out: Record<string, unknown> = { write, dir, marker };
      try {
        out.directory_snapshot = await this.container.snapshotDirectory({ dir, name });
      } catch (err) {
        out.directory_snapshot_error = err instanceof Error ? err.message : String(err);
      }
      if (p.full === true) {
        try {
          out.container_snapshot = await this.container.snapshotContainer({ name: `${name}-full` });
        } catch (err) {
          out.container_snapshot_error = err instanceof Error ? err.message : String(err);
        }
      }
      return out;
    },

    /** W-CTR-09 — restart from a snapshot handle and look for the runtime marker. */
    restore: async (p) => {
      const c = this.container;
      const destroyError = await this.destroyBounded();
      const opts: ContainerStartupOptions = { enableInternet: true };
      if (p.directory_snapshot && typeof p.directory_snapshot === "object") {
        opts.directorySnapshots = [
          {
            snapshot: p.directory_snapshot as ContainerDirectorySnapshot,
            ...(typeof p.mount_point === "string" ? { mountPoint: p.mount_point } : {}),
          },
        ];
      }
      if (p.container_snapshot && typeof p.container_snapshot === "object") {
        opts.containerSnapshot = p.container_snapshot as ContainerSnapshot;
      }
      let startError: string | null = null;
      try {
        await this.ensureRunning(opts);
      } catch (err) {
        startError = err instanceof Error ? err.message : String(err);
      }
      const dir = typeof p.dir === "string" ? p.dir : "/tmp/wulf";
      const look = await this.shell(
        `cat ${JSON.stringify(`${dir}/marker.txt`)} 2>&1; echo "---"; cat /srv/baseline.txt 2>&1`,
      );
      return {
        destroy_error: destroyError,
        start_error: startError,
        restored_with: opts,
        marker_lookup: look,
        running: c.running,
      };
    },

    /** W-CTR-10 — reroute the container's egress into a Worker binding. */
    intercept: async (p) => {
      await this.ensureRunning();
      const c = this.container;
      const mode = String(p.mode ?? "http");
      const addr = String(p.addr ?? "example.com:80");
      const applied: Record<string, unknown> = { mode, addr };
      try {
        if (mode === "https") await c.interceptOutboundHttps(addr, this.env.INTERCEPT_SINK);
        else if (mode === "tcp") await c.interceptOutboundTcp(addr, this.env.INTERCEPT_SINK);
        else if (mode === "all") await c.interceptAllOutboundHttp(this.env.INTERCEPT_SINK);
        else await c.interceptOutboundHttp(addr, this.env.INTERCEPT_SINK);
        applied.installed = true;
      } catch (err) {
        applied.installed = false;
        applied.error = err instanceof Error ? err.message : String(err);
      }
      const target = String(p.probe_url ?? `http://${addr.split(":")[0]}/`);
      applied.after = await this.shell(
        `curl -sS -m 6 ${JSON.stringify(target)} | head -c 400`,
        {},
        10_000,
      );
      return applied;
    },

    /** W-CTR-11 — reach container-internal listeners from the isolate. */
    tcp_port: async (p) => {
      await this.ensureRunning();
      const port = Number(p.port ?? 8080);
      const path = typeof p.path === "string" ? p.path : "/";
      const out: Record<string, unknown> = { port, path };
      // Optionally stand up an *undeclared* listener with exec() first — a port that
      // was never named as a defaultPort or in EXPOSE.
      if (p.spawn_listener === true) {
        const proc = await this.container.exec([
          "sh",
          "-c",
          `mkdir -p /tmp/srv2 && printf '%s' '{"listener":"exec-spawned","canary":"flag{w-ctr-11-undeclared-port}"}' > /tmp/srv2/index.html && busybox httpd -f -p ${port} -h /tmp/srv2`,
        ]);
        out.listener_pid = proc.pid;
        await new Promise((r) => setTimeout(r, 750));
      }
      try {
        const fetcher = this.container.getTcpPort(port);
        const res = await fetcher.fetch(`http://container-local${path}`);
        out.status = res.status;
        out.body = (await res.text()).slice(0, 500);
        out.reachable = true;
      } catch (err) {
        out.reachable = false;
        out.error = err instanceof Error ? err.message : String(err);
      }
      return out;
    },

    /** Rail: tear the container down between probes that need a clean baseline. */
    destroy: async () => {
      const error = await this.destroyBounded();
      return { destroyed: error === null, error, running: this.container.running };
    },
  };

  /**
   * W-CTR-03 — the shape from the demo: an HTTP request body handed straight to a
   * process's stdin, with the consumer chosen by the caller. No buffering in the
   * isolate; `req.body` is the ReadableStream the runtime hands us.
   */
  private async opStdin(req: Request, url: URL): Promise<Response> {
    await this.ensureRunning();
    const rawCmd = url.searchParams.get("cmd");
    const cmd: string[] = rawCmd ? (JSON.parse(rawCmd) as string[]) : ["cat"];
    const declared = Number(req.headers.get("content-length") ?? "0");
    if (declared > STDIN_CAP_BYTES) {
      return json({ error: "payload_too_large", declared, cap: STDIN_CAP_BYTES }, 413);
    }
    if (!req.body) return json({ error: "no_body" }, 400);

    const started = Date.now();
    let proc: ExecProcess | null = null;
    try {
      proc = await this.container.exec(cmd, {
        stdin: req.body,
        stdout: "pipe",
        stderr: "pipe",
      });
      const handle = proc;
      const timer = setTimeout(() => {
        try {
          handle.kill(9);
        } catch {
          /* gone */
        }
      }, EXEC_TIMEOUT_MS);
      const out = await handle.output();
      clearTimeout(timer);
      const se = decodeCapped(out.stderr);
      return json({
        ok: out.exitCode === 0,
        cmd,
        pid: handle.pid,
        exit_code: out.exitCode,
        declared_content_length: declared,
        // The fidelity oracle: for `cat`, stdout_sha256 must equal the sha the probe
        // computed over the bytes it sent. For ffmpeg, the magic bytes say whether a
        // real transcode happened.
        stdout_bytes: out.stdout.byteLength,
        stdout_sha256: await sha256Hex(out.stdout),
        stdout_magic_hex: hexPrefix(out.stdout),
        stderr_tail: se.text.slice(-1500),
        duration_ms: Date.now() - started,
      });
    } catch (err) {
      return json(
        {
          ok: false,
          cmd,
          error: err instanceof Error ? err.message : String(err),
          duration_ms: Date.now() - started,
        },
        200,
      );
    } finally {
      try {
        proc?.kill();
      } catch {
        /* gone */
      }
    }
  }
}

/**
 * W-CTR-10 — the interception sink. `interceptOutbound*()` reroutes the container's
 * egress here; a container process that prints this canary proves its "direct"
 * connection was transparently rerouted into Worker code.
 */
export class InterceptSink extends WorkerEntrypoint<Env> {
  override async fetch(req: Request): Promise<Response> {
    return json({
      sink: "InterceptSink",
      canary: "flag{w-ctr-10-egress-intercepted}",
      observed_url: req.url,
      observed_method: req.method,
      observed_host: req.headers.get("host"),
      observed_at: new Date().toISOString(),
    });
  }
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    // Gate everything, including the banner — an unauthenticated caller should not be
    // able to confirm what this Worker is.
    if (!authorized(req, env)) return json({ error: "forbidden" }, 403);

    if (url.pathname === "/" || url.pathname === "/ops") {
      return json({ worker: "wulf-container", wave: 6, route: "POST /ctr/<op>" });
    }
    if (!url.pathname.startsWith("/ctr/")) return json({ error: "not_found" }, 404);

    // One object per instance name. The probes use "wulf-ctr" for the shared target
    // and pass ?instance=<name> when a probe needs a *different* instance (W-CTR-09
    // carries a snapshot from one instance into another).
    const name = url.searchParams.get("instance") ?? "wulf-ctr";
    const stub = env.CTR_TARGET.get(env.CTR_TARGET.idFromName(name));
    return stub.fetch(req);
  },
};
