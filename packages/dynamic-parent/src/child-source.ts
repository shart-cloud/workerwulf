/**
 * Source code loaded into the Dynamic Worker isolate.
 *
 * Kept as a template string so wrangler does not need a bundler step to
 * embed it. The child receives a single fetch invocation per probe; the
 * `cmd` query param selects which in-sandbox routine to execute. The child
 * returns a JSON payload that the parent wraps into a ProbeResult.
 */
export const CHILD_SOURCE = `
export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const cmd = url.searchParams.get('cmd');
    try {
      const out = await dispatch(cmd, url, env, ctx, req);
      return new Response(JSON.stringify({ ok: true, data: out }), {
        headers: { 'content-type': 'application/json' },
      });
    } catch (err) {
      return new Response(
        JSON.stringify({
          ok: false,
          error: err && err.message ? err.message : String(err),
          stack: err && err.stack ? err.stack : null,
        }),
        { status: 500, headers: { 'content-type': 'application/json' } },
      );
    }
  },
};

async function dispatch(cmd, url, env, ctx, req) {
  switch (cmd) {
    case 'enumerate-globals':       return enumerateGlobals();
    case 'enumerate-env':           return enumerateEnv(env);
    case 'probe-parent':            return probeParentLeakage(env, ctx);
    case 'try-fetch':               return tryFetch(url.searchParams.get('target'));
    case 'rpc-exfil':               return rpcExfil(url.searchParams.get('payload-size'));
    case 'deep-env-walk':           return deepEnvWalk(env);
    case 'cf-dump':                 return cfDump(req);
    case 'ctx-shape':               return ctxShape(ctx);
    case 'kv-exfil':                return kvExfil(env, url.searchParams.get('binding') || 'CHILD_KV');
    case 'r2-exfil':                return r2Exfil(env, url.searchParams.get('binding') || 'CHILD_R2');
    case 'd1-exfil':                return d1Exfil(env, url.searchParams.get('binding') || 'CHILD_D1');
    case 'do-exec-sql':             return doExecSql(env, url.searchParams.get('binding') || 'CHILD_DO', url.searchParams);
    case 'do-stub-enum':            return doStubEnum(env, url.searchParams.get('binding') || 'CHILD_DO');
    case 'do-cross-object':         return doCrossObject(env, url.searchParams.get('binding') || 'CHILD_DO', url.searchParams.get('target_name') || 'other');
    case 'do-websocket-hibernate':  return doWebSocketHibernate(env, url.searchParams.get('binding') || 'CHILD_DO');
    case 'do-alarm-schedule':       return doAlarmSchedule(env, url.searchParams.get('binding') || 'CHILD_DO');
    case 'dyn-eval':               return dynEval();
    default: throw new Error('unknown cmd: ' + cmd);
  }
}

function enumerateGlobals() {
  const g = globalThis;
  const names = Object.getOwnPropertyNames(g).sort();
  const byKind = {};
  for (const n of names) {
    const v = g[n];
    const kind = v === null ? 'null' : typeof v;
    (byKind[kind] = byKind[kind] || []).push(n);
  }
  return { total: names.length, names, by_kind: byKind };
}

function enumerateEnv(env) {
  const entries = [];
  if (env && typeof env === 'object') {
    for (const k of Object.keys(env)) {
      const v = env[k];
      const t = typeof v;
      entries.push({
        name: k,
        type: t,
        constructor: v && t === 'object' ? (v.constructor && v.constructor.name) || null : null,
        preview: t === 'string' ? String(v).slice(0, 64)
               : (t === 'number' || t === 'boolean') ? String(v) : null,
      });
    }
  }
  return { count: entries.length, entries, env_is_null: env == null };
}

function probeParentLeakage(env, ctx) {
  // Reflection-based attempts to reach parent scope from inside the isolate.
  const findings = {};

  // 1. Walk env prototype chain looking for hidden parent props
  const envProtoChain = [];
  if (env) {
    let p = Object.getPrototypeOf(env);
    let depth = 0;
    while (p && depth < 8) {
      envProtoChain.push({
        constructor: p.constructor && p.constructor.name,
        keys: Object.getOwnPropertyNames(p),
      });
      p = Object.getPrototypeOf(p);
      depth++;
    }
  }
  findings.env_proto_chain = envProtoChain;

  // 2. ctx introspection
  const ctxKeys = [];
  if (ctx) {
    for (const k of Object.getOwnPropertyNames(ctx)) ctxKeys.push(k);
    let p = Object.getPrototypeOf(ctx);
    while (p && p !== Object.prototype) {
      for (const k of Object.getOwnPropertyNames(p)) if (ctxKeys.indexOf(k) < 0) ctxKeys.push(k);
      p = Object.getPrototypeOf(p);
    }
  }
  findings.ctx_keys = ctxKeys;
  findings.ctx_props = ctx && ctx.props != null ? typeof ctx.props : 'absent';
  findings.ctx_exports = ctx && ctx.exports != null
    ? Object.getOwnPropertyNames(ctx.exports)
    : 'absent';

  // 3. Stack trace probe
  try { throw new Error('probe'); } catch (e) {
    findings.stack_sample = String(e.stack || '').split('\\n').slice(0, 10);
  }

  // 4. Strict-mode caller probe (should throw)
  try {
    findings.arguments_callee = typeof arguments !== 'undefined' ? 'visible' : 'not-in-scope';
  } catch (e) {
    findings.arguments_callee = 'threw: ' + e.message;
  }

  // 5. Cross-realm Object reference
  findings.global_object_same_as_parent = false; // can't compare from inside
  findings.globalThis_constructor = globalThis.constructor && globalThis.constructor.name;

  return findings;
}

async function tryFetch(target) {
  if (!target) throw new Error('missing target');
  const started = Date.now();
  try {
    const res = await fetch(target, { signal: AbortSignal.timeout(2000) });
    const text = await res.text();
    return {
      reachable: true,
      status: res.status,
      latency_ms: Date.now() - started,
      body_preview: text.slice(0, 256),
    };
  } catch (err) {
    return {
      reachable: false,
      latency_ms: Date.now() - started,
      error: err && err.message ? err.message : String(err),
      error_name: err && err.name ? err.name : null,
    };
  }
}

function rpcExfil(sizeParam) {
  const size = Math.min(parseInt(sizeParam || '4096', 10) || 4096, 10_000_000);
  // Construct a payload that would be "stolen data" — fill with a recognizable
  // pattern so the harness can confirm exfiltration via RPC return value.
  const chunk = 'EXFIL:';
  let body = '';
  while (body.length < size) body += chunk;
  return {
    requested_size: size,
    actual_size: body.length,
    sha256_hint: 'pattern=EXFIL: repeated',
    payload: body.slice(0, size),
  };
}

function deepEnvWalk(env) {
  if (!env || typeof env !== 'object') {
    return { env_is_null: true };
  }
  const own = [];
  for (const key of Object.getOwnPropertyNames(env)) {
    const desc = Object.getOwnPropertyDescriptor(env, key);
    let v;
    try { v = env[key]; } catch { v = '<threw>'; }
    own.push({
      name: key,
      kind: desc && (('get' in desc) || ('set' in desc)) ? 'accessor' : 'data',
      enumerable: !!(desc && desc.enumerable),
      configurable: !!(desc && desc.configurable),
      type: typeof v,
      constructor: v && typeof v === 'object' ? (v.constructor && v.constructor.name) || null : null,
    });
  }
  const symbols = Object.getOwnPropertySymbols(env).map(s => s.toString());
  const proto_chain = [];
  let p = Object.getPrototypeOf(env);
  let depth = 0;
  while (p && p !== Object.prototype && depth < 8) {
    proto_chain.push({
      constructor: (p.constructor && p.constructor.name) || null,
      keys: Object.getOwnPropertyNames(p),
    });
    p = Object.getPrototypeOf(p);
    depth++;
  }
  return {
    enumerable_count: Object.keys(env).length,
    own_property_count: own.length,
    own,
    own_symbols: symbols,
    proto_chain,
    hidden_from_enumerable: own.filter(o => !o.enumerable).map(o => o.name),
  };
}

function cfDump(req) {
  const cf = {};
  const cfRaw = req && req.cf;
  if (cfRaw && typeof cfRaw === 'object') {
    for (const k of Object.keys(cfRaw)) cf[k] = cfRaw[k];
  }
  const cf_headers = {};
  if (req && req.headers && typeof req.headers.entries === 'function') {
    for (const [n, v] of req.headers.entries()) {
      const ln = n.toLowerCase();
      if (ln.startsWith('cf-') || ln === 'x-real-ip') cf_headers[n] = v;
    }
  }
  return {
    cf_present: cfRaw != null,
    cf_type: typeof cfRaw,
    cf_keys: Object.keys(cf),
    cf,
    cf_headers,
  };
}

function ctxShape(ctx) {
  if (!ctx) return { ctx_is_null: true };
  const own_keys = Object.getOwnPropertyNames(ctx);
  const own_symbols = Object.getOwnPropertySymbols(ctx).map(s => s.toString());
  const proto_chain = [];
  let p = Object.getPrototypeOf(ctx);
  let depth = 0;
  while (p && p !== Object.prototype && depth < 8) {
    proto_chain.push({
      constructor: (p.constructor && p.constructor.name) || null,
      keys: Object.getOwnPropertyNames(p),
    });
    p = Object.getPrototypeOf(p);
    depth++;
  }
  const probed = {};
  for (const name of ['props', 'exports', 'tracing', 'cache', 'waitUntil', 'passThroughOnException']) {
    try {
      const v = ctx[name];
      probed[name] = {
        type: typeof v,
        constructor: v && typeof v === 'object' ? (v.constructor && v.constructor.name) : null,
        preview: typeof v === 'function'
          ? ('function ' + (v.name || ''))
          : (v && typeof v === 'object' ? Object.getOwnPropertyNames(v) : v),
      };
    } catch (e) {
      probed[name] = { error: e && e.message ? e.message : String(e) };
    }
  }
  return { own_keys, own_symbols, proto_chain, probed };
}

async function kvExfil(env, bindingName) {
  const kv = env && env[bindingName];
  if (!kv) return { error: 'binding-not-present', binding: bindingName };
  const listed = await kv.list({ limit: 1000 });
  const keys = listed.keys.map(k => k.name);
  const samples = [];
  for (const k of keys.slice(0, 50)) {
    const v = await kv.get(k);
    samples.push({
      key: k,
      found: v !== null,
      value_preview: v ? v.slice(0, 256) : null,
      value_length: v ? v.length : 0,
    });
  }
  return {
    binding: bindingName,
    total_keys: keys.length,
    list_complete: listed.list_complete,
    samples,
  };
}

async function r2Exfil(env, bindingName) {
  const bucket = env && env[bindingName];
  if (!bucket) return { error: 'binding-not-present', binding: bindingName };
  const listed = await bucket.list({ limit: 1000 });
  const keys = listed.objects.map(o => ({ key: o.key, size: o.size }));
  const samples = [];
  for (const obj of listed.objects.slice(0, 20)) {
    const fetched = await bucket.get(obj.key);
    if (!fetched) continue;
    const buf = await fetched.arrayBuffer();
    const text = new TextDecoder('utf-8').decode(buf.slice(0, 4096));
    samples.push({ key: obj.key, size: obj.size, body_preview: text.slice(0, 512) });
  }
  return { binding: bindingName, total_objects: keys.length, sample_keys: keys, samples };
}

async function d1Exfil(env, bindingName) {
  const db = env && env[bindingName];
  if (!db) return { error: 'binding-not-present', binding: bindingName };
  const schema = await db
    .prepare("SELECT type, name, tbl_name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name")
    .all();
  const tables = (schema.results || []).filter(r => r.type === 'table');
  const dumps = [];
  for (const t of tables) {
    try {
      const safe = t.name.replace(/"/g, '""');
      const rows = await db.prepare('SELECT * FROM "' + safe + '" LIMIT 50').all();
      dumps.push({ table: t.name, rows: rows.results || [] });
    } catch (e) {
      dumps.push({ table: t.name, error: e && e.message ? e.message : String(e) });
    }
  }
  return { binding: bindingName, schema: schema.results || [], dumps };
}

// ---------- Durable Object commands for DO-DYN composition tests ----------

async function doExecSql(env, bindingName, params) {
  const rpc = env && (env.CHILD_DO_RPC || env[bindingName]);
  if (rpc && typeof rpc.execSql === 'function') {
    return {
      binding: 'CHILD_DO_RPC',
      do_name: params.get('name') || 'dyn-test',
      status: 200,
      body: { ok: true, data: await rpc.execSql({
        name: params.get('name') || 'dyn-test',
        cmd: params.get('do_cmd') || params.get('op') || 'classic-sqli',
        input: params.get('input') || '',
      }) },
    };
  }
  const ns = env && env[bindingName];
  if (!ns) return { error: 'binding-not-present', binding: bindingName };
  const id = ns.idFromName(params.get('name') || 'dyn-test');
  const stub = ns.get(id);
  const cmd = params.get('do_cmd') || params.get('op') || 'classic-sqli';
  const input = params.get('input') || '';
  const basePath = cmd ? '/' + cmd : '/';
  const doUrl = 'http://do' + basePath + (input ? '?input=' + encodeURIComponent(input) : '');
  const res = await stub.fetch(doUrl);
  return {
    binding: bindingName,
    do_name: params.get('name') || 'dyn-test',
    status: res.status,
    body: await res.json(),
  };
}

function doStubEnum(env, bindingName) {
  const rpc = env && (env.CHILD_DO_RPC || env[bindingName]);
  if (rpc && typeof rpc.stubEnum === 'function') return rpc.stubEnum();
  const ns = env && env[bindingName];
  if (!ns) return { error: 'binding-not-present', binding: bindingName };
  const id = ns.idFromName('enum-test');
  const stub = ns.get(id);
  const methods = [];
  let proto = Object.getPrototypeOf(stub);
  while (proto && proto !== Object.prototype) {
    for (const m of Object.getOwnPropertyNames(proto)) {
      if (m === 'constructor') continue;
      const desc = Object.getOwnPropertyDescriptor(proto, m);
      if (desc && typeof desc.value === 'function' && !methods.includes(m)) {
        methods.push(m);
      }
    }
    proto = Object.getPrototypeOf(proto);
  }
  return {
    binding: bindingName,
    stub_methods: methods.sort(),
    stub_constructor: stub.constructor && stub.constructor.name,
  };
}

async function doCrossObject(env, bindingName, targetName) {
  const rpc = env && (env.CHILD_DO_RPC || env[bindingName]);
  if (rpc && typeof rpc.crossObject === 'function') return rpc.crossObject({ targetName });
  const ns = env && env[bindingName];
  if (!ns) return { error: 'binding-not-present', binding: bindingName };
  const originalName = 'original';
  const markerUser = 'marker-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 8);
  const originalId = ns.idFromName(originalName);
  const guessedId = ns.idFromName(targetName);
  const originalStub = ns.get(originalId);
  const guessedStub = ns.get(guessedId);
  await checkedDoFetch(originalStub, 'http://do/init-schema');
  await checkedDoFetch(guessedStub, 'http://do/init-schema');
  const payload = "admin'; INSERT INTO users (username, password, secret) VALUES ('" + markerUser + "', 'marker', 'd-do-03-marker'); SELECT * FROM users WHERE username = 'admin";
  await checkedDoFetch(originalStub, 'http://do/stacked-query?input=' + encodeURIComponent(payload));
  const guessed = await checkedDoFetch(guessedStub, 'http://do/classic-sqli?input=' + encodeURIComponent(markerUser));
  const rows = guessed && guessed.data && guessed.data.rows ? guessed.data.rows : [];
  return {
    binding: bindingName,
    original_name: originalName,
    guessed_name: targetName,
    original_id: originalId.toString(),
    guessed_id: guessedId.toString(),
    ids_equal: originalId.toString() === guessedId.toString(),
    marker_user: markerUser,
    marker_visible_from_guessed_object: rows.length > 0,
    note: 'Child can obtain stubs for any name on a namespace it is explicitly given; marker visibility checks whether guessed names share object state.',
  };
}

async function doWebSocketHibernate(env, bindingName) {
  const rpc = env && (env.CHILD_DO_RPC || env[bindingName]);
  if (rpc && typeof rpc.webSocketHibernation === 'function') return rpc.webSocketHibernation();
  const ns = env && env[bindingName];
  if (!ns) return { error: 'binding-not-present', binding: bindingName };
  return {
    binding: bindingName,
    websocket_upgrade_supported: null,
    hibernation_api_callable: false,
    note: 'The child has no DO ctx, so acceptWebSocket()/hibernation APIs are not directly callable through a namespace binding. This requires an explicit DO fetch/RPC API to expose WebSocket behavior.',
  };
}

async function doAlarmSchedule(env, bindingName) {
  const rpc = env && (env.CHILD_DO_RPC || env[bindingName]);
  if (rpc && typeof rpc.alarmSchedule === 'function') return rpc.alarmSchedule();
  const ns = env && env[bindingName];
  if (!ns) return { error: 'binding-not-present', binding: bindingName };
  return {
    binding: bindingName,
    alarm_api_callable: false,
    note: 'The child has no DO ctx/storage reference, so ctx.storage.setAlarm() is not directly callable through a namespace binding. It would require an explicit DO fetch/RPC method.',
  };
}

function dynEval() {
  const results = {};

  // Test 1: basic eval
  try {
    results.eval_basic = eval('1 + 1');
    results.eval_available = true;
  } catch (err) {
    results.eval_available = false;
    results.eval_basic_error = err && err.message ? err.message : String(err);
  }

  // Test 2: can eval modify globals?
  const marker = 'dyn-child-marker-' + Date.now().toString(36);
  if (results.eval_available) {
    try {
      eval('globalThis.__childEvalMarker = "' + marker + '"');
      results.can_modify_globals = globalThis.__childEvalMarker === marker;
      delete globalThis.__childEvalMarker;
    } catch (err) {
      results.can_modify_globals = false;
      results.modify_error = err && err.message ? err.message : String(err);
    }
  }

  // Test 3: new Function() inside child
  try {
    const fn = new Function('return 42');
    results.function_ctor_available = fn() === 42;
    results.function_ctor_result = fn();
  } catch (err) {
    results.function_ctor_available = false;
    results.function_ctor_error = err && err.message ? err.message : String(err);
  }

  // Test 4: Function constructor can access globals
  if (results.function_ctor_available) {
    try {
      const fn = new Function('return typeof globalThis !== "undefined"');
      results.function_ctor_has_global = fn();
    } catch (err) {
      results.function_ctor_has_global = false;
      results.function_ctor_global_error = err && err.message ? err.message : String(err);
    }
  }

  // Test 5: dynamic import in child
  try {
    // import is syntax, not a value; compile a dynamic import expression instead.
    const importFn = new Function('specifier', 'return import(specifier)');
    results.dynamic_import_expression_compiles = typeof importFn === 'function';
  } catch (err) {
    results.dynamic_import_expression_compiles = false;
    results.import_check_error = err && err.message ? err.message : String(err);
  }

  // Test 6: enumerate globals that are relevant
  results.globals_of_interest = {
    eval_present: typeof eval !== 'undefined',
    Function_present: typeof Function !== 'undefined',
    eval_typeof: typeof eval,
    Function_typeof: typeof Function,
  };

  return results;
}

async function checkedDoFetch(stub, url, init) {
  const res = await stub.fetch(url, init);
  const body = await res.json();
  if (!res.ok || body.ok === false) {
    throw new Error(body && body.error ? body.error : 'Durable Object request failed with ' + res.status);
  }
  return body;
}
`;
