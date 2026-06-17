import type { ProbeResult } from "@wulf/shared";

/**
 * Intentionally vulnerable Durable Object for SQL injection testing.
 * Uses string concatenation / template literals instead of parameterized queries.
 */
export class PreyDurableObject implements DurableObject {
  private sql: SqlStorage;
  private state: DurableObjectState;

  constructor(state: DurableObjectState, _env: unknown) {
    this.state = state;
    this.sql = state.storage.sql;
  }

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const cmd = url.pathname.slice(1); // strip leading /

    try {
      const out = await this.dispatch(cmd, url, req);
      return json({ ok: true, data: out });
    } catch (err) {
      return json(
        {
          ok: false,
          error: err instanceof Error ? err.message : String(err),
          stack: err instanceof Error ? err.stack : null,
        },
        500,
      );
    }
  }

  private async dispatch(
    cmd: string,
    url: URL,
    _req: Request,
  ): Promise<unknown> {
    switch (cmd) {
      case "init-schema":
        return this.initSchema();
      case "classic-sqli": {
        const input = url.searchParams.get("input") ?? "";
        return this.classicSqli(input);
      }
      case "stacked-query": {
        const input = url.searchParams.get("input") ?? "";
        return this.stackedQuery(input);
      }
      case "union-inject": {
        const input = url.searchParams.get("input") ?? "";
        return this.unionInject(input);
      }
      case "blind-bool": {
        const input = url.searchParams.get("input") ?? "";
        return this.blindBool(input);
      }
      case "blind-time": {
        const input = url.searchParams.get("input") ?? "";
        return this.blindTime(input);
      }
      case "error-based": {
        const input = url.searchParams.get("input") ?? "";
        return this.errorBased(input);
      }
      case "pragma-list": {
        const pragma = url.searchParams.get("pragma") ?? "";
        return this.pragmaList(pragma);
      }
      case "attach-db": {
        const path = url.searchParams.get("path") ?? "";
        return this.attachDb(path);
      }
      case "cf-kv-table":
        return this.cfKvTable();
      case "sqlite-master":
        return this.sqliteMaster();
      case "load-extension": {
        const ext = url.searchParams.get("ext") ?? "";
        return this.loadExtension(ext);
      }
      case "file-io": {
        const path = url.searchParams.get("path") ?? "";
        return this.fileIo(path);
      }
      case "storage-dos": {
        const size = parseInt(url.searchParams.get("size") ?? "100", 10);
        return this.storageDos(size);
      }
      case "pitr-abuse":
        return this.pitrAbuse();
      case "raw-schema":
        return this.rawSchema();
      case "idor-put": {
        const key = url.searchParams.get("key") ?? "";
        const val = url.searchParams.get("val") ?? "";
        return this.idorPut(key, val);
      }
      case "idor-get": {
        const key = url.searchParams.get("key") ?? "";
        return this.idorGet(key);
      }
      default:
        throw new Error(`unknown cmd: ${cmd}`);
    }
  }

  private initSchema(): unknown {
    // Seed tables for injection targets
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT,
        password TEXT,
        secret TEXT
      )
    `);
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS notes (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        content TEXT
      )
    `);
    this.sql.exec(`
      INSERT OR IGNORE INTO users (id, username, password, secret)
      VALUES (1, 'admin', 'hunter2', 'flag{do-sql-01}'),
             (2, 'guest', 'guest', 'nothing-here')
    `);
    this.sql.exec(`
      INSERT OR IGNORE INTO notes (id, user_id, content)
      VALUES (1, 1, 'admin note'),
             (2, 2, 'guest note')
    `);
    return { initialized: true };
  }

  // ---------- SQL Injection (intentionally vulnerable) ----------

  private classicSqli(input: string): unknown {
    // VULNERABLE: direct string interpolation
    const query = `SELECT * FROM users WHERE username = '${input}'`;
    const cursor = this.sql.exec(query);
    const rows = [...cursor];
    return { query, rows };
  }

  private stackedQuery(input: string): unknown {
    // VULNERABLE: allows stacked queries via string concat
    const query = `SELECT * FROM users WHERE username = '${input}'`;
    const cursor = this.sql.exec(query);
    const rows = [...cursor];
    return { query, rows };
  }

  private unionInject(input: string): unknown {
    // VULNERABLE: UNION injection
    const query = `SELECT id, username FROM users WHERE username = '${input}'`;
    const cursor = this.sql.exec(query);
    const rows = [...cursor];
    return { query, rows };
  }

  private blindBool(input: string): unknown {
    // VULNERABLE: boolean-based blind
    const query = `SELECT * FROM users WHERE username = '${input}'`;
    const cursor = this.sql.exec(query);
    const rows = [...cursor];
    return { query, row_count: rows.length, rows };
  }

  private blindTime(input: string): unknown {
    const t0 = Date.now();
    // VULNERABLE: time-based blind via injected delay
    const query = `SELECT * FROM users WHERE username = '${input}'`;
    const cursor = this.sql.exec(query);
    const rows = [...cursor];
    return { query, row_count: rows.length, elapsed_ms: Date.now() - t0 };
  }

  private errorBased(input: string): unknown {
    // VULNERABLE: error-based schema disclosure
    const query = `SELECT * FROM users WHERE id = ${input}`;
    try {
      const cursor = this.sql.exec(query);
      const rows = [...cursor];
      return { query, rows, error: null };
    } catch (err) {
      return {
        query,
        rows: [],
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  // ---------- SQLite-Specific Attack Surface ----------

  private pragmaList(pragma: string): unknown {
    try {
      const cursor = this.sql.exec(`PRAGMA ${pragma}`);
      const rows = [...cursor];
      return { pragma, allowed: true, rows };
    } catch (err) {
      return {
        pragma,
        allowed: false,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  private attachDb(path: string): unknown {
    try {
      this.sql.exec(`ATTACH DATABASE '${path}' AS attached`);
      return { path, allowed: true };
    } catch (err) {
      return {
        path,
        allowed: false,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  private cfKvTable(): unknown {
    try {
      const cursor = this.sql.exec("SELECT * FROM __cf_kv LIMIT 10");
      const rows = [...cursor];
      return { exists: true, rows };
    } catch (err) {
      return {
        exists: false,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  private sqliteMaster(): unknown {
    const cursor = this.sql.exec(
      "SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY type, name",
    );
    return { rows: [...cursor] };
  }

  private loadExtension(ext: string): unknown {
    try {
      this.sql.exec(`SELECT load_extension('${ext}')`);
      return { ext, allowed: true };
    } catch (err) {
      return {
        ext,
        allowed: false,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  private fileIo(path: string): unknown {
    const results: Record<string, unknown> = {};
    try {
      this.sql.exec(`SELECT writefile('${path}', 'wulf-test')`);
      results.writefile = "succeeded";
    } catch (err) {
      results.writefile = err instanceof Error ? err.message : String(err);
    }
    try {
      const cursor = this.sql.exec(`SELECT readfile('${path}') AS content`);
      results.readfile = [...cursor];
    } catch (err) {
      results.readfile = err instanceof Error ? err.message : String(err);
    }
    return results;
  }

  private storageDos(size: number): unknown {
    // Attempt to fill storage with junk to probe limits
    const batch = Math.min(size, 1000);
    let inserted = 0;
    const t0 = Date.now();
    try {
      this.sql.exec("CREATE TABLE IF NOT EXISTS junk (id INTEGER PRIMARY KEY, blob BLOB)");
      for (let i = 0; i < batch; i++) {
        const blob = "x".repeat(1024); // 1KB per row
        this.sql.exec(`INSERT INTO junk (blob) VALUES ('${blob}')`);
        inserted++;
      }
      return { inserted, elapsed_ms: Date.now() - t0, limit_reached: false };
    } catch (err) {
      return {
        inserted,
        elapsed_ms: Date.now() - t0,
        limit_reached: true,
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }

  private pitrAbuse(): unknown {
    // Attempt to call PITR restore API from inside the DO
    // This should fail — PITR is an account-level API, not a DO runtime API.
    return {
      pitr_api_accessible: false,
      note: "PITR is exposed via Cloudflare REST API, not sql.exec",
    };
  }

  // ---------- Per-instance private store (DO-IDOR-* addressing tests) ----------
  //
  // Parameterized ON PURPOSE. These routes model a real app pattern — a Durable
  // Object that holds one principal's private data, selected by the DO *name*
  // (e.g. `account-1000`). The security property under test in DO-IDOR-* is
  // whether that name is guessable, NOT query safety, so we keep these bindings
  // parameterized to isolate the addressing/IDOR variable from SQL injection.

  private idorPut(key: string, val: string): unknown {
    this.sql.exec(
      "CREATE TABLE IF NOT EXISTS idor_secrets (key TEXT PRIMARY KEY, val TEXT)",
    );
    this.sql.exec(
      "INSERT OR REPLACE INTO idor_secrets (key, val) VALUES (?, ?)",
      key,
      val,
    );
    return { stored: true, key };
  }

  private idorGet(key: string): unknown {
    this.sql.exec(
      "CREATE TABLE IF NOT EXISTS idor_secrets (key TEXT PRIMARY KEY, val TEXT)",
    );
    const cursor = this.sql.exec(
      "SELECT val FROM idor_secrets WHERE key = ?",
      key,
    );
    const rows = [...cursor];
    return {
      key,
      found: rows.length > 0,
      val: (rows[0]?.val as string | undefined) ?? null,
    };
  }

  private rawSchema(): unknown {
    const tables: Array<{ name: string; columns: string[] }> = [];
    const tblCursor = this.sql.exec(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
    );
    for (const row of tblCursor) {
      const name = row.name as string;
      const colCursor = this.sql.exec(`PRAGMA table_info(${name})`);
      const columns: string[] = [];
      for (const col of colCursor) {
        columns.push(col.name as string);
      }
      tables.push({ name, columns });
    }
    return { tables };
  }
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: { "content-type": "application/json" },
  });
}
