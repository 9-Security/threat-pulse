/**
 * MCP server for the SOC IoC corpus, served from Cloudflare Workers over D1.
 *
 * The daily job pushes confirmed indicators here; this Worker only reads them.
 * It never scrapes, never writes, and never returns article bodies - those stay
 * in the audit JSON, because they are 26 publishers' text and no query needs
 * them.
 */

export interface Env {
  DB: D1Database;
  /** Fallback single token, for a deployment that has not issued any yet. */
  BOOTSTRAP_TOKEN?: string;
}

const PROTOCOL_VERSION = "2025-06-18";
const MAX_LIMIT = 200;
const DEFAULT_LIMIT = 40;
/** A log can name many hosts; cap the batch so one call cannot scan forever. */
const MAX_BATCH = 100;

type Json = Record<string, unknown>;

interface Caller {
  label: string;
  scopes: Set<string>;
}

/* -------------------------------------------------------------- auth ----- */

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Constant-time compare, so a wrong token cannot be found byte by byte. */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function authenticate(request: Request, env: Env): Promise<Caller | null> {
  const header = request.headers.get("authorization") ?? "";
  if (!header.startsWith("Bearer ")) return null;
  const presented = header.slice(7).trim();
  if (!presented) return null;

  const hash = await sha256Hex(presented);
  const row = await env.DB.prepare(
    `SELECT label, scopes, expires_at, revoked_at
       FROM tokens WHERE token_sha256 = ?`,
  )
    .bind(hash)
    .first<{ label: string; scopes: string; expires_at: string | null; revoked_at: string | null }>();

  if (row) {
    if (row.revoked_at) return null;
    if (row.expires_at && new Date(row.expires_at) < new Date()) return null;
    // Usage is recorded so an unused or runaway token is visible later.
    await env.DB.prepare(
      `UPDATE tokens SET last_used_at = ?, call_count = call_count + 1
         WHERE token_sha256 = ?`,
    )
      .bind(new Date().toISOString(), hash)
      .run();
    return { label: row.label, scopes: new Set(row.scopes.split(/[,\s]+/).filter(Boolean)) };
  }

  if (env.BOOTSTRAP_TOKEN && timingSafeEqual(presented, env.BOOTSTRAP_TOKEN)) {
    return { label: "bootstrap", scopes: new Set(["read", "context"]) };
  }
  return null;
}

/* ------------------------------------------------------------- shaping --- */

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

function validDate(value: unknown): string | null {
  return typeof value === "string" && DATE_RE.test(value) ? value : null;
}

function clampLimit(value: unknown): number {
  const n = typeof value === "number" ? Math.floor(value) : DEFAULT_LIMIT;
  return Math.min(Math.max(n, 1), MAX_LIMIT);
}

/**
 * A log names the host that actually resolved, which is often a child of the
 * host the report named. Try the value and each parent down to the registrable
 * pair, so `a.b.evil.com` still finds `evil.com`.
 */
function hostCandidates(value: string): string[] {
  const host = value.trim().toLowerCase().replace(/\.$/, "");
  if (!host.includes(".") || /^[\d.]+$/.test(host)) return [host];
  const labels = host.split(".");
  const out: string[] = [];
  for (let i = 0; i <= labels.length - 2; i += 1) out.push(labels.slice(i).join("."));
  return out;
}

function rowToHit(row: Json, caller: Caller): Json {
  const hit: Json = {
    report_date: row.report_date,
    indicator_type: row.indicator_type,
    value: row.value,
    status: row.status,
    action: row.action,
    priority: row.priority,
    reason: row.reason,
    kev: row.kev === null || row.kev === undefined ? null : Boolean(row.kev),
    kev_due_date: row.kev_due_date,
    cvss_score: row.cvss_score,
    cvss_severity: row.cvss_severity,
    source: row.source,
    article_title: row.article_title,
    article_url: row.article_url,
    section: row.section,
  };
  // The context line is a verbatim source sentence. A token without the scope
  // gets the citation and can read it at the publisher.
  if (caller.scopes.has("context")) hit.context = row.context ?? null;
  return hit;
}

/* --------------------------------------------------------------- tools --- */

const TOOLS = [
  {
    name: "list_reports",
    description: "List ingested daily reports, newest first, with their counts.",
    inputSchema: {
      type: "object",
      properties: { limit: { type: "number", description: "max reports (default 40)" } },
    },
  },
  {
    name: "get_report_summary",
    description:
      "One report's subject, window, priority line and patch/block/hunt/KEV counts. Omit date for the newest.",
    inputSchema: {
      type: "object",
      properties: { date: { type: "string", description: "YYYY-MM-DD" } },
    },
  },
  {
    name: "search_confirmed_iocs",
    description:
      "Search confirmed indicators across every ingested day. Filter by text, action (patch/block/hunt), indicator_type, or a single date.",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string" },
        date: { type: "string", description: "YYYY-MM-DD; omit to search all days" },
        since: { type: "string", description: "YYYY-MM-DD lower bound" },
        action: { type: "string" },
        indicator_type: { type: "string" },
        limit: { type: "number" },
      },
    },
  },
  {
    name: "lookup_ioc",
    description:
      "Look one indicator up across every day. For a hostname it also tries each parent domain, so a log's FQDN still matches a report's apex.",
    inputSchema: {
      type: "object",
      properties: {
        value: { type: "string" },
        since: { type: "string", description: "YYYY-MM-DD lower bound" },
      },
      required: ["value"],
    },
  },
  {
    name: "lookup_iocs",
    description:
      "Look up many indicators at once - the values pulled out of a log - and get every day each one was reported. Up to 100 per call.",
    inputSchema: {
      type: "object",
      properties: {
        values: { type: "array", items: { type: "string" } },
        since: { type: "string", description: "YYYY-MM-DD lower bound" },
      },
      required: ["values"],
    },
  },
] as const;

async function listReports(env: Env, args: Json): Promise<Json> {
  const { results } = await env.DB.prepare(
    `SELECT report_date, subject, article_count, confirmed_ioc_count,
            patch_count, block_count, hunt_count, kev_count, unavailable_count,
            generated_at
       FROM reports ORDER BY report_date DESC LIMIT ?`,
  )
    .bind(clampLimit(args.limit))
    .all<Json>();
  return { count: results.length, reports: results };
}

async function reportSummary(env: Env, args: Json): Promise<Json> {
  const date = validDate(args.date);
  const row = date
    ? await env.DB.prepare(`SELECT * FROM reports WHERE report_date = ?`).bind(date).first<Json>()
    : await env.DB.prepare(`SELECT * FROM reports ORDER BY report_date DESC LIMIT 1`).first<Json>();
  if (!row) return { error: date ? `no report for ${date}` : "no reports ingested yet" };
  let enrichment: unknown = null;
  try {
    enrichment = JSON.parse(String(row.enrichment_json ?? "{}"));
  } catch {
    enrichment = null;
  }
  const { enrichment_json, ...rest } = row;
  return { ...rest, enrichment };
}

async function searchIocs(env: Env, args: Json, caller: Caller): Promise<Json> {
  const clauses: string[] = ["status = 'confirmed'"];
  const binds: unknown[] = [];
  const date = validDate(args.date);
  const since = validDate(args.since);
  if (date) {
    clauses.push("report_date = ?");
    binds.push(date);
  } else if (since) {
    clauses.push("report_date >= ?");
    binds.push(since);
  }
  if (typeof args.action === "string" && args.action) {
    clauses.push("action = ?");
    binds.push(args.action.toLowerCase());
  }
  if (typeof args.indicator_type === "string" && args.indicator_type) {
    clauses.push("indicator_type = ?");
    binds.push(args.indicator_type.toLowerCase());
  }
  if (typeof args.query === "string" && args.query.trim()) {
    clauses.push("(value LIKE ? OR article_title LIKE ? OR reason LIKE ?)");
    const like = `%${args.query.trim()}%`;
    binds.push(like, like, like);
  }
  const limit = clampLimit(args.limit);
  const { results } = await env.DB.prepare(
    `SELECT * FROM indicators WHERE ${clauses.join(" AND ")}
      ORDER BY report_date DESC, indicator_type, value LIMIT ?`,
  )
    .bind(...binds, limit)
    .all<Json>();
  return {
    count: results.length,
    truncated: results.length >= limit,
    items: results.map((row) => rowToHit(row, caller)),
  };
}

async function lookupMany(env: Env, values: string[], since: string | null, caller: Caller) {
  const wanted = values
    .filter((v) => typeof v === "string" && v.trim())
    .slice(0, MAX_BATCH)
    .map((v) => v.trim());

  const candidateMap = new Map<string, string[]>();
  const allCandidates = new Set<string>();
  for (const value of wanted) {
    const candidates = hostCandidates(value);
    // A hash or CVE is matched as given, only hosts expand upward.
    const list = /^[0-9a-f]{32,64}$/i.test(value) || /^cve-/i.test(value)
      ? [value.toLowerCase()]
      : candidates;
    candidateMap.set(value, list);
    list.forEach((c) => allCandidates.add(c));
  }
  if (allCandidates.size === 0) return [];

  // D1 allows 100 bound parameters per query, and one hostname expands to a
  // candidate per label, so 40 FQDNs already overrun a single statement.
  const PARAMS_PER_QUERY = 90;
  const byValue = new Map<string, Json[]>();
  const candidates = [...allCandidates];
  for (let start = 0; start < candidates.length; start += PARAMS_PER_QUERY) {
    const chunk = candidates.slice(start, start + PARAMS_PER_QUERY);
    const placeholders = chunk.map(() => "?").join(",");
    const binds: unknown[] = [...chunk];
    // value_lc is indexed; wrapping the column in LOWER() would force a scan.
    let sql = `SELECT * FROM indicators WHERE value_lc IN (${placeholders})`;
    if (since) {
      sql += " AND report_date >= ?";
      binds.push(since);
    }
    sql += " ORDER BY report_date DESC";
    const { results } = await env.DB.prepare(sql).bind(...binds).all<Json>();
    for (const row of results) {
      const key = String(row.value).toLowerCase();
      if (!byValue.has(key)) byValue.set(key, []);
      byValue.get(key)!.push(row);
    }
  }

  return wanted.map((value) => {
    const candidates = candidateMap.get(value) ?? [];
    const hits: Json[] = [];
    let matchedOn: string | null = null;
    for (const candidate of candidates) {
      const rows = byValue.get(candidate);
      if (rows && rows.length) {
        matchedOn = candidate;
        hits.push(...rows.map((row) => rowToHit(row, caller)));
        break; // the most specific match wins
      }
    }
    const dates = [...new Set(hits.map((h) => String(h.report_date)))].sort();
    return {
      value,
      found: hits.length > 0,
      matched_on: matchedOn,
      exact: matchedOn !== null && matchedOn === value.toLowerCase(),
      first_seen: dates[0] ?? null,
      last_seen: dates[dates.length - 1] ?? null,
      seen_on: dates,
      hits,
    };
  });
}

/* ------------------------------------------------------------ dispatch --- */

async function callTool(name: string, args: Json, env: Env, caller: Caller): Promise<Json> {
  switch (name) {
    case "list_reports":
      return listReports(env, args);
    case "get_report_summary":
      return reportSummary(env, args);
    case "search_confirmed_iocs":
      return searchIocs(env, args, caller);
    case "lookup_ioc": {
      const value = typeof args.value === "string" ? args.value : "";
      if (!value) return { error: "value is required" };
      const [only] = await lookupMany(env, [value], validDate(args.since), caller);
      return only ?? { value, found: false, hits: [] };
    }
    case "lookup_iocs": {
      const values = Array.isArray(args.values) ? (args.values as string[]) : [];
      if (!values.length) return { error: "values must be a non-empty array" };
      const items = await lookupMany(env, values, validDate(args.since), caller);
      return {
        requested: values.length,
        examined: items.length,
        found: items.filter((i) => i.found).length,
        items,
      };
    }
    default:
      return { error: `unknown tool: ${name}` };
  }
}

function rpcResult(id: unknown, result: unknown): Response {
  return Response.json({ jsonrpc: "2.0", id, result });
}

function rpcError(id: unknown, code: number, message: string, status = 200): Response {
  return Response.json({ jsonrpc: "2.0", id, error: { code, message } }, { status });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return Response.json({ ok: true, server: "iocs" });
    }
    if (url.pathname !== "/mcp") {
      return new Response("not found", { status: 404 });
    }
    if (request.method !== "POST") {
      return new Response("method not allowed", { status: 405, headers: { allow: "POST" } });
    }

    const caller = await authenticate(request, env);
    if (!caller) {
      return Response.json(
        { error: "unauthorized" },
        { status: 401, headers: { "www-authenticate": "Bearer" } },
      );
    }

    let body: Json;
    try {
      body = (await request.json()) as Json;
    } catch {
      return rpcError(null, -32700, "parse error");
    }
    const id = body.id ?? null;
    const method = String(body.method ?? "");
    const params = (body.params ?? {}) as Json;

    switch (method) {
      case "initialize":
        return rpcResult(id, {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: { tools: {} },
          serverInfo: { name: "iocs", version: "1.0.0" },
          instructions:
            "Confirmed IoCs from daily SOC reports, with the action and reason this " +
            "project derived and the source article for each. Read-only; no live " +
            "scraping. Use lookup_iocs for the values pulled out of a log.",
        });
      case "notifications/initialized":
        return new Response(null, { status: 202 });
      case "tools/list":
        return rpcResult(id, { tools: TOOLS });
      case "tools/call": {
        const name = String((params.name as string) ?? "");
        const args = (params.arguments ?? {}) as Json;
        try {
          const result = await callTool(name, args, env, caller);
          return rpcResult(id, {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
            isError: Boolean((result as Json).error),
          });
        } catch (error) {
          return rpcResult(id, {
            content: [{ type: "text", text: `tool ${name} failed: ${String(error)}` }],
            isError: true,
          });
        }
      }
      default:
        return rpcError(id, -32601, `method not found: ${method}`);
    }
  },
};
