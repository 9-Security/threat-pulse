/**
 * `enrich_observables`: the offline validator's answer, served from D1.
 *
 * Every rule here is a port of `tools/corpus-validator/validate.py`, the tool the
 * MSSP has run against the signed bundle: the same defanging, type detection, skip
 * rules, decision order, held-back rule and citation requirement. The hosted
 * service reports the same `corpus_version` as a bundle built from the same days,
 * so an answer from here and an answer from the bundle can be compared value by
 * value. Where this file departs from the validator, a comment says why.
 *
 * Import-free, with the database and the suffix rules injected, so the rules are
 * tested under plain node.
 */

import { classify, MAX_BATCH, parseIPv4, parseIPv6, isGlobalIPv4, isGlobalIPv6, INTERNAL_SUFFIXES } from "./guard.ts";

/* -------------------------------------------------------------- constants --- */

/** The types the bundle carries, and so the only ones answered. */
export const OBSERVABLE_TYPES = ["cve", "domain", "ip", "url", "md5", "sha1", "sha256"] as const;
export type ObservableType = (typeof OBSERVABLE_TYPES)[number];
/** Relations counted in the headline rate; `child_domain` is reported but not counted. */
export const HEADLINE_METHODS = ["exact", "parent_domain", "same_host"] as const;
export type MatchMethod = "exact" | "same_host" | "parent_domain" | "child_domain";
export type SkipCode =
  | "empty_value"
  | "invalid_value"
  | "non_public_ip"
  | "internal_hostname"
  | "sensitive_url"
  | "request_limit"
  | "unsupported_type";
export type ErrorCode = "lookup_failed" | "time_budget_exceeded" | "missing_citation";

export const SCOPE_NOTE =
  "Published vendor and CERT reporting only. No passive DNS, no sandbox, no AV consensus, no reputation scoring.";
export const VERDICT_NOTE =
  "verdict states what a publisher reported. suggested_investigation_action and priority are this service's own analysis and are not safe to automate without consumer policy.";
export const ABSENCE_NOTE =
  "unseen means the value is not named in this corpus over the days it covers. It is not a clean or benign verdict and must not be treated as one.";

const CVE_RE = /^CVE-\d{4}-\d{4,7}$/i;
const MD5_RE = /^[0-9a-f]{32}$/i;
const SHA1_RE = /^[0-9a-f]{40}$/i;
const SHA256_RE = /^[0-9a-f]{64}$/i;
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

/* -------------------------------------------------------------- defanging --- */

const DEFANG_RULES: Array<[string, string]> = [
  ["[.]", "."],
  ["(.)", "."],
  ["{.}", "."],
  ["[:]", ":"],
  ["[://]", "://"],
  ["[dot]", "."],
  ["(dot)", "."],
];
const DEFANG_SCHEMES: Array<[string, string]> = [
  ["hxxps", "https"],
  ["hxxp", "http"],
  ["fxp", "ftp"],
];
const escapeRe = (text: string) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const DEFANG_TOKEN_RE = new RegExp(DEFANG_RULES.map(([token]) => escapeRe(token)).join("|"), "gi");
const DEFANG_REPLACEMENTS = new Map(DEFANG_RULES.map(([token, real]) => [token.toLowerCase(), real]));

/** The real value, and every normalization applied to reach it. */
export function undefang(value: string): { text: string; applied: string[] } {
  let text = value.trim();
  const applied: string[] = [];
  for (let pass = 0; pass < 4; pass += 1) {
    const before = text;
    const replaced = text.replace(DEFANG_TOKEN_RE, (m) => DEFANG_REPLACEMENTS.get(m.toLowerCase()) ?? m);
    if (replaced !== text) {
      text = replaced;
      if (!applied.includes("defang")) applied.push("defang");
    }
    const lowered = text.toLowerCase();
    for (const [fanged, real] of DEFANG_SCHEMES) {
      if (lowered.startsWith(`${fanged}://`)) {
        text = real + text.slice(fanged.length);
        if (!applied.includes("defang_scheme")) applied.push("defang_scheme");
        break;
      }
    }
    if (text === before) break;
  }
  text = text.trim();
  if (text.endsWith(".") && !text.includes("://")) {
    text = text.replace(/\.+$/, "");
    applied.push("trailing_dot");
  }
  return { text, applied };
}

/* --------------------------------------------------------- classification --- */

export function detectType(value: string): ObservableType | "empty" | "unknown" {
  const text = value.trim();
  if (!text) return "empty";
  if (CVE_RE.test(text)) return "cve";
  if (MD5_RE.test(text)) return "md5";
  if (SHA1_RE.test(text)) return "sha1";
  if (SHA256_RE.test(text)) return "sha256";
  if (text.includes("://")) return "url";
  if (parseIPv4(text) !== null || parseIPv6(text) !== null) return "ip";
  if (DOMAIN_RE.test(text.replace(/\.+$/, ""))) return "domain";
  return "unknown";
}

/**
 * The host of a URL as Python's `urlsplit(...).hostname` gives it: lower case,
 * without user info, port or IPv6 brackets. The WHATWG parser is not used, because
 * it rewrites hosts (`0x7f.1` becomes `127.0.0.1`) where Python does not, and the
 * corpus was keyed by Python.
 */
export function urlHost(value: string): string {
  const afterScheme = value.slice(value.indexOf("://") + 3);
  const authority = afterScheme.split(/[/?#]/, 1)[0];
  const hostPort = authority.slice(authority.lastIndexOf("@") + 1);
  if (hostPort.startsWith("[")) {
    const end = hostPort.indexOf("]");
    return end === -1 ? "" : hostPort.slice(1, end).toLowerCase();
  }
  return hostPort.split(":", 1)[0].toLowerCase();
}

/** Python's compressed IPv6 text: lower case, the first longest zero run as `::`. */
export function formatIPv6(address: bigint): string {
  const groups: number[] = [];
  for (let i = 7; i >= 0; i -= 1) groups.push(Number((address >> BigInt(i * 16)) & 0xffffn));
  let bestStart = -1;
  let bestLength = 0;
  let runStart = -1;
  groups.forEach((group, i) => {
    if (group !== 0) {
      runStart = -1;
      return;
    }
    if (runStart < 0) runStart = i;
    if (i - runStart + 1 > bestLength) {
      bestLength = i - runStart + 1;
      bestStart = runStart;
    }
  });
  const hex = groups.map((group) => group.toString(16));
  if (bestLength > 1) {
    return `${hex.slice(0, bestStart).join(":")}::${hex.slice(bestStart + bestLength).join(":")}`;
  }
  return hex.join(":");
}

export function normalize(value: string, kind: string): string {
  const text = value.trim();
  if (kind === "cve") return text.toUpperCase();
  if (kind === "md5" || kind === "sha1" || kind === "sha256") return text.toLowerCase();
  if (kind === "url") return urlHost(text);
  if (kind === "domain") return text.replace(/\.+$/, "").toLowerCase();
  if (kind === "ip") {
    if (parseIPv4(text) !== null) return text;
    const zone = text.indexOf("%");
    const v6 = parseIPv6(text);
    if (v6 !== null) return formatIPv6(v6) + (zone === -1 ? "" : text.slice(zone));
    return text;
  }
  return text.toLowerCase();
}

function isInternalName(host: string): boolean {
  return !host.includes(".") || INTERNAL_SUFFIXES.some((suffix) => host.endsWith(suffix));
}

function skipFor(value: string, kind: string): SkipCode | null {
  if (kind === "empty") return "empty_value";
  if (kind === "unknown") return "unsupported_type";
  if (kind === "ip") {
    const v4 = parseIPv4(value);
    if (v4 !== null) return isGlobalIPv4(v4, value) ? null : "non_public_ip";
    const v6 = parseIPv6(value);
    // The validator reports `malformed_ip`; this service's code for it is `invalid_value`.
    if (v6 === null) return "invalid_value";
    return isGlobalIPv6(v6) ? null : "non_public_ip";
  }
  if (kind === "domain" || kind === "url") {
    const host = normalize(value, kind);
    // The validator reports `unparseable_host`.
    if (!host) return "invalid_value";
    const v4 = parseIPv4(host);
    if (v4 !== null && !isGlobalIPv4(v4, host)) return "non_public_ip";
    const v6 = host.includes(":") ? parseIPv6(host) : null;
    if (v6 !== null && !isGlobalIPv6(v6)) return "non_public_ip";
    if (v4 === null && v6 === null && isInternalName(host)) return "internal_hostname";
  }
  return null;
}

/** A safety skip from either the supplied or the detected type wins; `unsupported_type` only if both say so. */
function skipReason(value: string, supplied: string, detected: string): SkipCode | null {
  const kinds = [...new Set([supplied, detected].filter(Boolean))];
  const reasons = kinds.map((kind) => skipFor(value, kind));
  const firm = reasons.find((reason) => reason && reason !== "unsupported_type");
  if (firm) return firm;
  if (reasons.length && reasons.every((reason) => reason === "unsupported_type")) return "unsupported_type";
  return null;
}

/* ------------------------------------------------------------------ store --- */

export interface IndicatorRow {
  /** Insertion order within the table; with `report_date`, the order the bundle reads rows in. */
  rid: number;
  report_date: string;
  indicator_type: string;
  value: string;
  value_lc: string;
  action: string | null;
  priority: string | null;
  reason: string | null;
  benign_basis: string | null;
  source: string | null;
  article_title: string | null;
  article_url: string | null;
  published_at: string | null;
  context: string | null;
  registrable_lc: string | null;
}

export interface ExcludedRow {
  report_date: string;
  indicator_type: string;
  value: string;
  value_lc: string;
  reason_codes: string; // JSON array
}

export interface CveRow {
  report_date: string;
  cve_id: string;
  record: string; // JSON object
}

export interface CorpusInfo {
  state: {
    corpus_version: string;
    days: number;
    first_date: string | null;
    last_date: string | null;
    publisher_count: number;
    psl_version: string | null;
  } | null;
  reports: Array<{ report_date: string; report_id: string; sources_failed: string | null }>;
}

export interface EnrichStore {
  /** Rows whose `value_lc` is one of `keys`, of the observable types, ordered by day then insertion. */
  indicators(keys: string[], since: string | null): Promise<IndicatorRow[]>;
  /** Domain rows whose `registrable_lc` is one of `registrables`, in the same order. */
  children(registrables: string[], since: string | null): Promise<IndicatorRow[]>;
  excluded(keys: string[], since: string | null): Promise<ExcludedRow[]>;
  cveIntel(ids: string[]): Promise<CveRow[]>;
  corpus(): Promise<CorpusInfo>;
}

export interface Boundaries {
  /** Ancestors of `host` down to its registrable domain, nearest first. */
  parents(host: string): string[];
  /** The registrable domain, or `host` itself when it is a public suffix. */
  registrable(host: string): string;
}

export interface EnrichDeps {
  store: EnrichStore;
  boundaries: Boundaries;
  now(): number;
  requestId(): string;
  budgetMs: number;
  chunkSize: number;
}

export interface EnrichRequest {
  values: unknown[];
  types?: unknown[] | null;
  detail?: "compact" | "full";
  since?: string | null;
  /** Whether the caller holds the `context` scope. */
  mayReadContext: boolean;
}

/* ----------------------------------------------------------------- plans --- */

interface Plan {
  index: number;
  value: string;
  normalized: string;
  applied: string[];
  supplied: string | null;
  used: ObservableType;
  warnings: string[];
  key: string;
  /** A URL compared whole: trimmed, lower case, trailing slashes dropped. */
  whole: string | null;
  parents: string[];
  registrable: string | null;
}

const whole = (url: string) => url.trim().replace(/\/+$/, "").toLowerCase();

type Group = "indicators" | "children" | "excluded" | "cve";
type Lost = Map<string, ErrorCode>;

async function runChunked<Row>(
  keys: string[],
  deps: EnrichDeps,
  started: number,
  lost: Lost,
  fetch: (chunk: string[]) => Promise<Row[]>,
): Promise<Row[]> {
  const out: Row[] = [];
  for (let start = 0; start < keys.length; start += deps.chunkSize) {
    const chunk = keys.slice(start, start + deps.chunkSize);
    if (deps.now() - started > deps.budgetMs) {
      chunk.forEach((key) => lost.set(key, "time_budget_exceeded"));
      continue;
    }
    try {
      out.push(...(await fetch(chunk)));
    } catch {
      // The database's message is neither returned nor logged.
      chunk.forEach((key) => lost.set(key, "lookup_failed"));
    }
  }
  return out;
}

/* --------------------------------------------------------------- records --- */

interface Citation {
  publisher: string | null;
  article_title: string | null;
  article_url: string;
  published_at: string | null;
  report_date: string;
  report_id: string | null;
  context?: string | null;
}

interface ValueRecord {
  value: string;
  type: string;
  reportDates: string[];
  publishers: string[];
  citations: Citation[];
  action: string | null;
  priority: string | null;
  reason: string | null;
  benignBasis: string | null;
}

function buildRecords(rows: IndicatorRow[], reportIds: Map<string, string>, withContext: boolean): Map<string, ValueRecord> {
  const records = new Map<string, ValueRecord>();
  for (const row of rows) {
    let record = records.get(row.value_lc);
    if (!record) {
      record = {
        value: row.value,
        type: row.indicator_type,
        reportDates: [],
        publishers: [],
        citations: [],
        action: null,
        priority: null,
        reason: null,
        benignBasis: null,
      };
      records.set(row.value_lc, record);
    }
    if (!record.reportDates.includes(row.report_date)) record.reportDates.push(row.report_date);
    if (row.source && !record.publishers.includes(row.source)) record.publishers.push(row.source);
    // One citation per publisher per article, first occurrence kept: the bundle's rule.
    if (
      row.article_url &&
      !record.citations.some((c) => c.publisher === row.source && c.article_url === row.article_url)
    ) {
      const citation: Citation = {
        publisher: row.source,
        article_title: row.article_title,
        article_url: row.article_url,
        published_at: row.published_at,
        report_date: row.report_date,
        report_id: reportIds.get(row.report_date) ?? null,
      };
      if (withContext) citation.context = row.context;
      record.citations.push(citation);
    }
    // The newest day that carried an action decides, as in the bundle.
    if (row.action) {
      record.action = row.action;
      record.priority = row.priority;
      record.reason = row.reason;
      record.benignBasis = row.benign_basis;
    }
  }
  for (const record of records.values()) record.reportDates.sort();
  return records;
}

function daysBetween(from: string, to: string): number {
  return Math.round((Date.parse(`${to}T00:00:00Z`) - Date.parse(`${from}T00:00:00Z`)) / 86_400_000);
}

function reasonCode(record: ValueRecord, intel: Record<string, unknown> | null): string {
  if (record.benignBasis) return record.benignBasis;
  if (record.type === "cve") {
    if (intel?.kev === true) return "kev_listed";
    const severity = typeof intel?.cvss_severity === "string" ? intel.cvss_severity.toLowerCase() : "";
    if (severity) return `cvss_${severity}`;
    return "cve_reported";
  }
  return "publisher_indicator";
}

function parseRecord(row: CveRow | undefined): Record<string, unknown> | null {
  if (!row) return null;
  try {
    const parsed = JSON.parse(row.record);
    return parsed && typeof parsed === "object" ? parsed : null;
  } catch {
    return null;
  }
}

function vulnerability(row: CveRow | undefined, record: Record<string, unknown> | null): Record<string, unknown> | null {
  if (!row || !record) return null;
  const pick = (key: string) => (record[key] === undefined ? null : record[key]);
  return {
    kev: {
      listed: typeof record.kev === "boolean" ? record.kev : null,
      date_added: pick("kev_date_added"),
      due_date: pick("kev_due_date"),
      known_ransomware: pick("kev_known_ransomware"),
    },
    cvss: {
      score: pick("cvss_score"),
      severity: pick("cvss_severity"),
      version: pick("cvss_version"),
      vector: pick("cvss_vector"),
    },
    nvd_status: pick("nvd_status"),
    epss: { score: pick("epss_score"), percentile: pick("epss_percentile"), date: pick("epss_date") },
    provenance: Array.isArray(record.sources) ? record.sources : [],
    retrieved_at: pick("retrieved_at"),
    observed_on: row.report_date,
  };
}

/* ------------------------------------------------------------------- run --- */

export async function enrichObservables(request: EnrichRequest, deps: EnrichDeps): Promise<Record<string, unknown>> {
  const started = deps.now();
  const detail = request.detail === "full" ? "full" : "compact";
  const since = typeof request.since === "string" && DATE_RE.test(request.since) ? request.since : null;
  const values = request.values;
  const types = Array.isArray(request.types) ? request.types : null;

  const hits: Array<Record<string, unknown>> = [];
  const excluded: Array<Record<string, unknown>> = [];
  const unseen: Array<Record<string, unknown>> = [];
  const skipped: Array<Record<string, unknown>> = [];
  const errors: Array<Record<string, unknown>> = [];
  const plans: Plan[] = [];

  values.forEach((raw, index) => {
    if (typeof raw !== "string") {
      skipped.push({ input_index: index, value: "", reason: "invalid_value" });
      return;
    }
    if (index >= MAX_BATCH) {
      skipped.push({ input_index: index, value: raw, reason: "request_limit" });
      return;
    }
    const { text, applied } = undefang(raw);
    const warnings: string[] = [];
    let supplied = types && typeof types[index] === "string" ? String(types[index]).trim().toLowerCase() : "";
    if (supplied && !(OBSERVABLE_TYPES as readonly string[]).includes(supplied)) {
      warnings.push(`unknown_supplied_type:${supplied.slice(0, 32)}`);
      supplied = "";
    }
    // This service's own guard runs first: it also refuses URLs carrying
    // credentials and values over the length and label limits.
    const guarded = classify(text);
    if (guarded) {
      skipped.push({ input_index: index, value: raw, reason: guarded, ...(warnings.length ? { warnings } : {}) });
      return;
    }
    const detected = detectType(text);
    if (supplied && detected !== "unknown" && detected !== "empty" && supplied !== detected) {
      warnings.push(`type_mismatch:supplied=${supplied},detected=${detected}`);
    }
    const reason = skipReason(text, supplied, detected);
    if (reason) {
      skipped.push({ input_index: index, value: raw, reason, ...(warnings.length ? { warnings } : {}) });
      return;
    }
    const used = (supplied || detected) as ObservableType;
    const normalized = normalize(text, used);
    const key = normalized.toLowerCase();
    const hostLike = used === "domain" || used === "url";
    plans.push({
      index,
      value: raw,
      normalized,
      applied,
      supplied: supplied || null,
      used,
      warnings,
      key,
      whole: used === "url" ? whole(text) : null,
      parents: hostLike ? deps.boundaries.parents(key) : [],
      registrable: hostLike ? deps.boundaries.registrable(key) : null,
    });
  });
  const truncated = values.length > MAX_BATCH;

  // What each plan needs from each query.
  const needs = (plan: Plan, group: Group): string[] => {
    const wholeKeys = plan.whole ? [plan.whole, `${plan.whole}/`] : [];
    if (group === "indicators") return [...new Set([...wholeKeys, plan.key, ...plan.parents])];
    if (group === "excluded") return [...new Set([...wholeKeys, plan.key])];
    if (group === "children") return plan.registrable ? [plan.registrable] : [];
    return plan.used === "cve" ? [plan.normalized] : [];
  };
  const union = (group: Group) => [...new Set(plans.flatMap((plan) => needs(plan, group)))];

  const lost: Record<Group, Lost> = {
    indicators: new Map(),
    children: new Map(),
    excluded: new Map(),
    cve: new Map(),
  };

  let corpus: CorpusInfo;
  try {
    corpus = await deps.store.corpus();
  } catch {
    // Without the corpus's extent no answer can be qualified: every value is unknown.
    for (const plan of plans) errors.push({ input_index: plan.index, value: plan.value, reason: "lookup_failed" });
    return respond(null, "failed");
  }

  const indicatorRows = await runChunked(union("indicators"), deps, started, lost.indicators, (chunk) =>
    deps.store.indicators(chunk, since),
  );
  const childRows = await runChunked(union("children"), deps, started, lost.children, (chunk) =>
    deps.store.children(chunk, since),
  );
  const excludedRows = await runChunked(union("excluded"), deps, started, lost.excluded, (chunk) =>
    deps.store.excluded(chunk, since),
  );
  const cveRows = await runChunked(union("cve"), deps, started, lost.cve, (chunk) => deps.store.cveIntel(chunk));

  const reportIds = new Map(corpus.reports.map((r) => [r.report_date, r.report_id]));
  const withContext = detail === "full" && request.mayReadContext;
  // A row can arrive through both queries. Merge them once, in the order the bundle
  // reads them, so first-seen and newest-action rules hold for every value.
  const rowsById = new Map<string, IndicatorRow>();
  for (const row of [...indicatorRows, ...childRows]) rowsById.set(`${row.report_date}|${row.rid}`, row);
  const allRows = [...rowsById.values()].sort((a, b) =>
    a.report_date === b.report_date ? a.rid - b.rid : a.report_date < b.report_date ? -1 : 1,
  );
  const records = buildRecords(allRows, reportIds, withContext);
  const domainsUnder = new Map<string, Set<string>>();
  for (const row of childRows) {
    if (row.indicator_type !== "domain" || !row.registrable_lc) continue;
    const set = domainsUnder.get(row.registrable_lc) ?? new Set<string>();
    set.add(row.value_lc);
    domainsUnder.set(row.registrable_lc, set);
  }
  const exclusions = new Map<string, { value: string; type: string; codes: string[]; dates: string[] }>();
  for (const row of excludedRows) {
    let entry = exclusions.get(row.value_lc);
    if (!entry) {
      entry = { value: row.value, type: row.indicator_type, codes: [], dates: [] };
      exclusions.set(row.value_lc, entry);
    }
    let codes: unknown = [];
    try {
      codes = JSON.parse(row.reason_codes);
    } catch {
      codes = [];
    }
    for (const code of Array.isArray(codes) ? codes : []) {
      if (!entry.codes.includes(String(code))) entry.codes.push(String(code));
    }
    if (!entry.dates.includes(row.report_date)) entry.dates.push(row.report_date);
  }
  const newestCve = new Map<string, CveRow>();
  for (const row of cveRows) {
    const current = newestCve.get(row.cve_id);
    if (!current || row.report_date > current.report_date) newestCve.set(row.cve_id, row);
  }

  const lastDate = corpus.reports.length ? corpus.reports.map((r) => r.report_date).sort().at(-1)! : null;
  const heldBack = (key: string) => Boolean(records.get(key)?.benignBasis);
  const storedWhole = (plan: Plan): string | null => {
    if (!plan.whole) return null;
    for (const candidate of [plan.whole, `${plan.whole}/`]) if (records.has(candidate)) return candidate;
    return null;
  };
  const excludedWhole = (plan: Plan): string | null => {
    if (!plan.whole) return null;
    for (const candidate of [plan.whole, `${plan.whole}/`]) if (exclusions.has(candidate)) return candidate;
    return null;
  };

  for (const plan of plans) {
    const failure = (["indicators", "children", "excluded", "cve"] as Group[])
      .flatMap((group) => needs(plan, group).map((key) => lost[group].get(key)))
      .find(Boolean);
    if (failure) {
      errors.push({ input_index: plan.index, value: plan.value, reason: failure });
      continue;
    }

    // The validator's match(), in its order.
    let method: MatchMethod | null = null;
    let matched: string | null = null;
    const exactWhole = storedWhole(plan);
    if (exactWhole) {
      method = "exact";
      matched = exactWhole;
    } else if (records.has(plan.key) && !(plan.used === "url" && heldBack(plan.key))) {
      method = plan.used === "url" ? "same_host" : "exact";
      matched = plan.key;
    } else if (plan.used === "domain" || plan.used === "url") {
      const parent = plan.parents.find((p) => records.has(p) && !heldBack(p));
      if (parent) {
        method = "parent_domain";
        matched = parent;
      } else {
        const children = [...(domainsUnder.get(plan.registrable ?? "") ?? [])]
          .filter((child) => child !== plan.key && child.endsWith(`.${plan.key}`) && !heldBack(child))
          .sort();
        if (children.length) {
          method = "child_domain";
          matched = children[0];
        }
      }
    }

    // The validator's exclusion(), in its order.
    let exclusion: string | null = null;
    if (method !== "exact") {
      exclusion = excludedWhole(plan);
      if (!exclusion && method !== "same_host" && exclusions.has(plan.key)) exclusion = plan.key;
    }

    const base = {
      input_index: plan.index,
      value: plan.value,
      normalized_value: plan.normalized,
      normalization_applied: plan.applied,
      type: plan.used,
      type_supplied: plan.supplied,
      ...(plan.warnings.length ? { warnings: plan.warnings } : {}),
    };

    if (exclusion) {
      const entry = exclusions.get(exclusion)!;
      excluded.push({
        ...base,
        matched_value: entry.value,
        reason_codes: entry.codes,
        report_dates: [...entry.dates].sort(),
      });
      continue;
    }
    if (!method || !matched) {
      unseen.push(base);
      continue;
    }
    const record = records.get(matched)!;
    if (!record.citations.length) {
      // A value that cannot be cited is never returned as a hit.
      errors.push({ input_index: plan.index, value: plan.value, reason: "missing_citation" });
      continue;
    }
    const intelRow = plan.used === "cve" ? newestCve.get(plan.normalized) : undefined;
    const intel = parseRecord(intelRow);
    const vuln = vulnerability(intelRow, intel);
    const lastSeen = record.reportDates.at(-1) ?? null;
    hits.push({
      ...base,
      verdict: record.benignBasis ? "benign_listed" : "source_reported",
      basis: record.benignBasis ? "service_rule" : "publisher_report",
      match: method,
      headline: (HEADLINE_METHODS as readonly string[]).includes(method),
      matched_value: record.value,
      match_boundary: method === "exact" ? null : method === "same_host" ? "host" : "registrable_domain",
      first_seen: record.reportDates[0] ?? null,
      last_seen: lastSeen,
      days_since_last_seen: lastSeen && lastDate ? daysBetween(lastSeen, lastDate) : null,
      report_count: record.reportDates.length,
      source_count: record.publishers.length,
      publishers: record.publishers,
      suggested_investigation_action: record.action,
      priority: record.priority,
      benign_basis: record.benignBasis,
      reason_code: reasonCode(record, intel),
      reason: record.reason,
      citation_count: record.citations.length,
      citations: detail === "full" ? record.citations : record.citations.slice(0, 1),
      vulnerability: vuln,
    });
  }

  const answered = hits.length + excluded.length + unseen.length;
  const status = errors.length === 0 ? (truncated ? "partial" : "complete") : answered === 0 ? "failed" : "partial";
  return respond(corpus, status);

  function respond(info: CorpusInfo | null, status: string): Record<string, unknown> {
    const reports = info?.reports ?? [];
    const dates = reports.map((r) => r.report_date).sort();
    const state = info?.state ?? null;
    // The version describes a set of days. Report it only while D1 holds exactly that set.
    const consistent =
      state !== null &&
      state.days === dates.length &&
      state.first_date === (dates[0] ?? null) &&
      state.last_date === (dates.at(-1) ?? null);
    const failures = reports
      .map((r) => {
        let failed: unknown = [];
        try {
          failed = JSON.parse(r.sources_failed ?? "[]");
        } catch {
          failed = [];
        }
        return { report_date: r.report_date, sources_failed: Array.isArray(failed) ? failed : [] };
      })
      .filter((day) => day.sources_failed.length)
      .sort((a, b) => (a.report_date < b.report_date ? -1 : 1));
    const processed = hits.length + excluded.length + unseen.length;
    return {
      status,
      request_id: deps.requestId(),
      generated_at: new Date(deps.now()).toISOString(),
      corpus_version: consistent ? state!.corpus_version : null,
      truncated,
      detail,
      since,
      coverage: {
        report_range: dates.length ? [dates[0], dates.at(-1)] : null,
        report_count: dates.length,
        source_count: state?.publisher_count ?? null,
        days_with_source_failures: failures,
        headline_methods: HEADLINE_METHODS,
        public_suffix_list_version: state?.psl_version ?? null,
        scope: SCOPE_NOTE,
        verdict_note: VERDICT_NOTE,
        absence_note: ABSENCE_NOTE,
        ...(info && !consistent
          ? { version_note: "corpus_version is withheld: the stored days do not match the days it was computed from." }
          : {}),
      },
      counts: {
        requested: values.length,
        processed,
        hits: hits.length,
        headline_hits: hits.filter((hit) => hit.headline).length,
        excluded: excluded.length,
        unseen: unseen.length,
        skipped: skipped.length,
        failed: errors.length,
      },
      hits,
      excluded,
      unseen,
      skipped: skipped.sort((a, b) => Number(a.input_index) - Number(b.input_index)),
      errors: errors.sort((a, b) => Number(a.input_index) - Number(b.input_index)),
    };
  }
}
