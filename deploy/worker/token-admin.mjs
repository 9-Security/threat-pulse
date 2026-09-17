#!/usr/bin/env node
/**
 * Client token administration for the query service.
 *
 *   node token-admin.mjs issue <label> [--scopes "read context"] [--per-minute N]
 *                                      [--per-day N] [--expires YYYY-MM-DD] [--out FILE]
 *   node token-admin.mjs revoke <label>
 *   node token-admin.mjs revoke-all --confirm yes
 *   node token-admin.mjs limits <label> [--per-minute N|default] [--per-day N|default]
 *   node token-admin.mjs list
 *   node token-admin.mjs usage [--days N]
 *
 * Run from the operator's workstation, in a terminal only the operator reads. It
 * uses the deploy token in ./.env and the D1 HTTP API with bound parameters, so
 * neither a token nor its hash ever appears in a statement's text, which D1 keeps
 * in its query insights. No command prints a hash.
 *
 * `issue` prints the new token exactly once - or, with --out, writes it to a file
 * readable only by you and prints nothing. Hand it to the client over a channel
 * separate from ordinary email; see docs/token-runbook.md.
 */
import { createHash, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const DATABASE_ID = "819cd0ac-bd1a-43bd-91fd-9a21a9d34dd3";
const here = dirname(fileURLToPath(import.meta.url));

function loadEnv() {
  const env = {};
  for (const line of readFileSync(join(here, ".env"), "utf8").split(/\r?\n/)) {
    const at = line.indexOf("=");
    if (at > 0) env[line.slice(0, at).trim()] = line.slice(at + 1).trim().replace(/^["']|["']$/g, "");
  }
  for (const name of ["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID"]) {
    if (!env[name]) throw new Error(`${name} is missing from ${join(here, ".env")}`);
  }
  return env;
}

async function query(env, sql, params = []) {
  const response = await fetch(
    `https://api.cloudflare.com/client/v4/accounts/${env.CLOUDFLARE_ACCOUNT_ID}/d1/database/${DATABASE_ID}/query`,
    {
      method: "POST",
      headers: { authorization: `Bearer ${env.CLOUDFLARE_API_TOKEN}`, "content-type": "application/json" },
      body: JSON.stringify({ sql, params }),
    },
  );
  const payload = await response.json();
  if (!response.ok || !payload.success) {
    const messages = (payload.errors ?? []).map((e) => e.message).join("; ");
    throw new Error(`D1 query failed (${response.status}): ${messages}`);
  }
  return payload.result[0];
}

function parseArgs(argv) {
  const positional = [];
  const options = {};
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i].startsWith("--")) options[argv[i].slice(2)] = argv[++i];
    else positional.push(argv[i]);
  }
  return { positional, options };
}

function limitOption(value, name) {
  if (value === undefined) return undefined;
  if (value === "default") return null;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 0) throw new Error(`--${name} must be a whole number, 0 to suspend, or "default"`);
  return n;
}

function table(rows) {
  if (!rows.length) return "(none)";
  const keys = Object.keys(rows[0]);
  const width = keys.map((k) => Math.max(k.length, ...rows.map((r) => String(r[k] ?? "").length)));
  const line = (cells) => cells.map((c, i) => String(c ?? "").padEnd(width[i])).join("  ");
  return [line(keys), line(width.map((w) => "-".repeat(w))), ...rows.map((r) => line(keys.map((k) => r[k])))].join("\n");
}

async function issue(env, label, options) {
  if (!label) throw new Error("issue needs a label");
  const active = await query(env, "SELECT COUNT(*) AS n FROM tokens WHERE label = ? AND revoked_at IS NULL", [label]);
  if (active.results[0].n > 0) {
    throw new Error(`an active token labelled "${label}" exists; revoke it first or choose another label`);
  }
  const scopes = options.scopes ?? "read";
  for (const scope of scopes.split(/[\s,]+/).filter(Boolean)) {
    if (!["read", "context"].includes(scope)) throw new Error(`unknown scope "${scope}"`);
  }
  let expires = null;
  if (options.expires !== undefined) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(options.expires)) throw new Error("--expires must be YYYY-MM-DD");
    expires = `${options.expires}T00:00:00Z`;
  }
  const token = randomBytes(32).toString("hex");
  const hash = createHash("sha256").update(token).digest("hex");
  await query(
    env,
    `INSERT INTO tokens (token_sha256, label, scopes, created_at, expires_at, rate_per_minute, rate_per_day)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [
      hash,
      label,
      scopes,
      new Date().toISOString(),
      expires,
      limitOption(options["per-minute"], "per-minute") ?? null,
      limitOption(options["per-day"], "per-day") ?? null,
    ],
  );
  if (options.out) {
    writeFileSync(options.out, `${token}\n`, { mode: 0o600, flag: "wx" });
    console.log(`Issued "${label}". The token is in ${options.out} and was not printed.`);
  } else {
    console.log(`Issued "${label}". It is shown once and cannot be recovered:\n\n  ${token}\n`);
    console.log("Send it over a channel separate from ordinary email. See docs/token-runbook.md.");
  }
}

async function revoke(env, label) {
  if (!label) throw new Error("revoke needs a label");
  const result = await query(
    env,
    "UPDATE tokens SET revoked_at = datetime('now') WHERE label = ? AND revoked_at IS NULL",
    [label],
  );
  const changed = result.meta?.changes ?? 0;
  console.log(changed ? `Revoked ${changed} token(s) labelled "${label}". It stops working on its next call.` : `No active token labelled "${label}".`);
}

async function revokeAll(env, options) {
  if (options.confirm !== "yes") throw new Error("revoke-all needs --confirm yes");
  const result = await query(env, "UPDATE tokens SET revoked_at = datetime('now') WHERE revoked_at IS NULL");
  console.log(`Revoked ${result.meta?.changes ?? 0} active token(s). Every call now gets 401 until a token is issued.`);
}

async function limits(env, label, options) {
  if (!label) throw new Error("limits needs a label");
  const sets = [];
  const params = [];
  for (const name of ["per-minute", "per-day"]) {
    const value = limitOption(options[name], name);
    if (value !== undefined) {
      sets.push(`${name === "per-minute" ? "rate_per_minute" : "rate_per_day"} = ?`);
      params.push(value);
    }
  }
  if (!sets.length) throw new Error("limits needs --per-minute and/or --per-day");
  const result = await query(env, `UPDATE tokens SET ${sets.join(", ")} WHERE label = ? AND revoked_at IS NULL`, [...params, label]);
  console.log(`Updated ${result.meta?.changes ?? 0} active token(s) labelled "${label}".`);
}

async function list(env) {
  const { results } = await query(
    env,
    `SELECT label, scopes, created_at, expires_at, revoked_at, last_used_at, call_count AS calls,
            COALESCE(rate_per_minute, 'default') AS per_minute, COALESCE(rate_per_day, 'default') AS per_day
       FROM tokens ORDER BY revoked_at IS NULL DESC, created_at`,
  );
  console.log(table(results));
}

async function usage(env, options) {
  const days = Number(options.days ?? 7);
  if (!Number.isInteger(days) || days < 1) throw new Error("--days must be a positive whole number");
  const since = new Date(Date.now() - (days - 1) * 86_400_000).toISOString().slice(0, 10);
  const { results } = await query(
    env,
    `SELECT substr(u.bucket, 3) AS day_utc, t.label, u.count AS calls, u.rejected
       FROM token_usage u JOIN tokens t ON t.token_sha256 = u.token_sha256
      WHERE u.bucket LIKE 'd:%' AND u.bucket >= ?
      ORDER BY day_utc DESC, t.label`,
    [`d:${since}`],
  );
  console.log(table(results));
}

const [command, ...rest] = process.argv.slice(2);
const { positional, options } = parseArgs(rest);
const commands = {
  issue: (env) => issue(env, positional[0], options),
  revoke: (env) => revoke(env, positional[0]),
  "revoke-all": (env) => revokeAll(env, options),
  limits: (env) => limits(env, positional[0], options),
  list: (env) => list(env),
  usage: (env) => usage(env, options),
};
if (!commands[command]) {
  console.error("usage: node token-admin.mjs issue|revoke|revoke-all|limits|list|usage ... (see the header of this file)");
  process.exit(2);
}
commands[command](loadEnv()).catch((error) => {
  console.error(String(error.message ?? error));
  process.exit(1);
});
