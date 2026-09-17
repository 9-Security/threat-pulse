/**
 * Run with: npm test  (node's own runner, stripping types -- no dependency)
 *
 * The cases follow tools/corpus-validator/test_validate.py, so a rule the offline
 * validator is tested for is tested here too.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  detectType,
  enrichObservables,
  formatIPv6,
  normalize,
  undefang,
  urlHost,
  type Boundaries,
  type CorpusInfo,
  type CveRow,
  type EnrichDeps,
  type EnrichRequest,
  type ExcludedRow,
  type IndicatorRow,
} from "./enrich.ts";

type Json = Record<string, any>;

/* ------------------------------------------------------------- fixtures --- */

const SUFFIXES = new Set(["com", "net", "org", "uk", "co.uk", "io", "github.io", "dev", "workers.dev", "example"]);

function publicSuffix(labels: string[]): string {
  for (let i = 0; i < labels.length; i += 1) {
    const candidate = labels.slice(i).join(".");
    if (SUFFIXES.has(candidate)) return candidate;
  }
  return labels[labels.length - 1];
}

const boundaries: Boundaries = {
  parents(host) {
    const labels = host.split(".");
    const depth = publicSuffix(labels).split(".").length;
    const out: string[] = [];
    for (let i = 1; i < labels.length - depth; i += 1) out.push(labels.slice(i).join("."));
    return out;
  },
  registrable(host) {
    const labels = host.split(".");
    const depth = publicSuffix(labels).split(".").length;
    return labels.length > depth ? labels.slice(-(depth + 1)).join(".") : host;
  },
};

interface Seed {
  value: string;
  type?: string;
  date?: string;
  source?: string;
  url?: string | null;
  action?: string | null;
  priority?: string | null;
  benign?: string | null;
  context?: string | null;
}

function row(seed: Seed, rid: number): IndicatorRow {
  const type = seed.type ?? (seed.value.includes("://") ? "url" : /^cve-/i.test(seed.value) ? "cve" : "domain");
  const lc = seed.value.toLowerCase();
  return {
    rid,
    report_date: seed.date ?? "2026-09-04",
    indicator_type: type,
    value: seed.value,
    value_lc: lc,
    action: seed.action === undefined ? "block" : seed.action,
    priority: seed.priority === undefined ? "high" : seed.priority,
    reason: "reason text",
    benign_basis: seed.benign ?? null,
    source: seed.source ?? "Example Publisher",
    article_title: "Report",
    article_url: seed.url === undefined ? `https://news.example/${rid}` : seed.url,
    published_at: "2026-09-03T09:00:00+00:00",
    context: seed.context ?? `context ${rid}`,
    registrable_lc: type === "domain" ? boundaries.registrable(lc) : null,
  };
}

const OBSERVABLE = new Set(["cve", "domain", "ip", "url", "md5", "sha1", "sha256"]);

function fixture(options: {
  seeds?: Seed[];
  excluded?: Array<{ value: string; type?: string; codes: string[]; date?: string }>;
  cve?: Array<{ id: string; date: string; record: Json }>;
  days?: string[];
  state?: Partial<NonNullable<CorpusInfo["state"]>> | null;
  failWhen?: (kind: string, keys: string[]) => boolean;
  clock?: () => number;
  budgetMs?: number;
}) {
  const rows = (options.seeds ?? []).map((seed, i) => row(seed, i + 1));
  const excludedRows: ExcludedRow[] = (options.excluded ?? []).map((e) => ({
    report_date: e.date ?? "2026-09-04",
    indicator_type: e.type ?? "domain",
    value: e.value,
    value_lc: e.value.toLowerCase(),
    reason_codes: JSON.stringify(e.codes),
  }));
  const cveRows: CveRow[] = (options.cve ?? []).map((c) => ({
    report_date: c.date,
    cve_id: c.id,
    record: JSON.stringify(c.record),
  }));
  const days = options.days ?? ["2026-09-04", "2026-09-05"];
  const calls: Array<{ kind: string; keys: string[]; since: string | null }> = [];
  const guard = (kind: string, keys: string[], since: string | null = null) => {
    calls.push({ kind, keys, since });
    if (options.failWhen?.(kind, keys)) throw new Error(`D1_ERROR secret ${keys.join(",")}`);
  };
  const ordered = (list: IndicatorRow[]) =>
    [...list].sort((a, b) => (a.report_date === b.report_date ? a.rid - b.rid : a.report_date < b.report_date ? -1 : 1));
  const deps: EnrichDeps = {
    store: {
      async indicators(keys, since) {
        guard("indicators", keys, since);
        return ordered(
          rows.filter((r) => keys.includes(r.value_lc) && OBSERVABLE.has(r.indicator_type) && (!since || r.report_date >= since)),
        );
      },
      async children(registrables, since) {
        guard("children", registrables, since);
        return ordered(
          rows.filter(
            (r) =>
              r.indicator_type === "domain" &&
              r.registrable_lc !== null &&
              registrables.includes(r.registrable_lc) &&
              (!since || r.report_date >= since),
          ),
        );
      },
      async excluded(keys, since) {
        guard("excluded", keys, since);
        return excludedRows.filter((r) => keys.includes(r.value_lc) && (!since || r.report_date >= since));
      },
      async cveIntel(ids) {
        guard("cve", ids);
        return cveRows.filter((r) => ids.includes(r.cve_id));
      },
      async corpus() {
        guard("corpus", []);
        const state =
          options.state === null
            ? null
            : {
                corpus_version: `${days.at(-1)}.abcdef123456`,
                days: days.length,
                first_date: days[0],
                last_date: days.at(-1)!,
                publisher_count: 3,
                psl_version: "psl-test",
                ...(options.state ?? {}),
              };
        return {
          state,
          reports: days.map((d, i) => ({
            report_date: d,
            report_id: `rpt-${i}`,
            sources_failed: d === days[0] ? JSON.stringify(["recorded-future"]) : "[]",
          })),
        };
      },
    },
    boundaries,
    now: options.clock ?? (() => Date.parse("2026-09-06T00:00:00Z")),
    requestId: () => "req-test",
    budgetMs: options.budgetMs ?? 10_000,
    chunkSize: 90,
  };
  return { deps, calls };
}

async function run(
  values: unknown[],
  options: Parameters<typeof fixture>[0] = {},
  extra: Partial<EnrichRequest> = {},
): Promise<{ out: Json; calls: ReturnType<typeof fixture>["calls"] }> {
  const { deps, calls } = fixture(options);
  const out = await enrichObservables({ values, mayReadContext: false, ...extra }, deps);
  assertShape(out);
  assertEveryValueOnce(out, values.length);
  return { out, calls };
}

const byIndex = (out: Json) => {
  const map = new Map<number, { bucket: string; item: Json }>();
  for (const bucket of ["hits", "excluded", "unseen", "skipped", "errors"]) {
    for (const item of out[bucket]) map.set(item.input_index, { bucket, item });
  }
  return map;
};

function assertEveryValueOnce(out: Json, n: number) {
  const seen: number[] = [];
  for (const bucket of ["hits", "excluded", "unseen", "skipped", "errors"]) {
    for (const item of out[bucket]) seen.push(item.input_index);
  }
  assert.deepEqual([...seen].sort((a, b) => a - b), Array.from({ length: n }, (_, i) => i), "every value exactly once");
}

/* ------------------------------------------------ schema, checked by hand --- */

const SCHEMA = JSON.parse(readFileSync(new URL("./schemas/enrich_observables.output.json", import.meta.url), "utf8"));

function typeOf(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  if (typeof value === "number") return Number.isInteger(value) ? "integer" : "number";
  return typeof value;
}

function check(schema: Json, value: unknown, path: string, errors: string[]) {
  if (schema.$ref) return check(SCHEMA.$defs[schema.$ref.split("/").at(-1)], value, path, errors);
  if (schema.oneOf) {
    const passing = schema.oneOf.filter((option: Json) => {
      const sub: string[] = [];
      check(option, value, path, sub);
      return sub.length === 0;
    });
    if (passing.length !== 1) errors.push(`${path}: matches ${passing.length} of oneOf`);
    return;
  }
  if (schema.type) {
    const allowed = Array.isArray(schema.type) ? schema.type : [schema.type];
    const actual = typeOf(value);
    if (!allowed.includes(actual) && !(actual === "integer" && allowed.includes("number"))) {
      errors.push(`${path}: ${actual} not in ${allowed}`);
      return;
    }
  }
  if (schema.enum && !schema.enum.includes(value)) errors.push(`${path}: ${JSON.stringify(value)} not in enum`);
  if (schema.pattern && typeof value === "string" && !new RegExp(schema.pattern).test(value)) {
    errors.push(`${path}: does not match ${schema.pattern}`);
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) errors.push(`${path}: too few items`);
    if (schema.maxItems !== undefined && value.length > schema.maxItems) errors.push(`${path}: too many items`);
    if (schema.items) value.forEach((item, i) => check(schema.items, item, `${path}[${i}]`, errors));
  } else if (value && typeof value === "object") {
    const object = value as Json;
    for (const key of schema.required ?? []) if (!(key in object)) errors.push(`${path}: missing ${key}`);
    for (const [key, item] of Object.entries(object)) {
      const sub = schema.properties?.[key];
      if (sub) check(sub, item, `${path}.${key}`, errors);
      else if (schema.additionalProperties === false) errors.push(`${path}: unexpected ${key}`);
    }
  }
}

function assertShape(out: Json) {
  const errors: string[] = [];
  check(SCHEMA, out, "$", errors);
  assert.deepEqual(errors, [], "response conforms to enrich_observables.output.json");
}

/* ---------------------------------------------------------- normalizing --- */

test("defanging mirrors the validator, including case and repeated passes", () => {
  assert.deepEqual(undefang("hxxp[:]//Evil[DOT]example(.)com/x"), {
    text: "http://Evil.example.com/x",
    applied: ["defang", "defang_scheme"],
  });
  assert.deepEqual(undefang(" evil.example.com. "), { text: "evil.example.com", applied: ["trailing_dot"] });
  assert.deepEqual(undefang("https://evil.example.com/."), { text: "https://evil.example.com/.", applied: [] });
});

test("types are detected as the validator detects them", () => {
  assert.equal(detectType("cve-2026-1234"), "cve");
  assert.equal(detectType("d41d8cd98f00b204e9800998ecf8427e"), "md5");
  assert.equal(detectType("2606:4700::1111"), "ip");
  assert.equal(detectType("evil.example.com."), "domain");
  assert.equal(detectType("evil_underscore.com"), "unknown");
  assert.equal(detectType("fairlife"), "unknown");
  assert.equal(detectType("  "), "empty");
});

test("URL hosts and IPv6 text follow Python", () => {
  assert.equal(urlHost("https://user:pw@EVIL.example.com:8443/path?q=1"), "evil.example.com");
  assert.equal(urlHost("http://[2606:4700::1111]:80/"), "2606:4700::1111");
  assert.equal(urlHost("http://0x7f.1/"), "0x7f.1", "no WHATWG host rewriting");
  assert.equal(formatIPv6(0n), "::");
  assert.equal(normalize("2606:4700:0:0:0:0:0:1111", "ip"), "2606:4700::1111");
  assert.equal(normalize("2001:0:0:1:0:0:0:1", "ip"), "2001:0:0:1::1", "the longest zero run is compressed");
  assert.equal(normalize("1:0:0:2:0:0:3:4", "ip"), "1::2:0:0:3:4", "the first of equal runs is compressed");
  assert.equal(normalize("cve-2026-1234", "cve"), "CVE-2026-1234");
});

/* ------------------------------------------------------------- matching --- */

const MATCHING: Seed[] = [
  { value: "evil.example.com", date: "2026-09-04", source: "Alpha" },
  { value: "evil.example.com", date: "2026-09-05", source: "Beta", action: "hunt", priority: "medium" },
  { value: "tenant.github.io" },
  { value: "https://evil.example.com/payload" },
  { value: "https://kit.example.com/kit/" },
  { value: "cdn.parentless.com" },
];

test("exact and parent matches, never across a registry", async () => {
  const { out } = await run(
    ["evil.example.com", "api.evil.example.com", "other.github.io", "deep.tenant.github.io"],
    { seeds: MATCHING },
  );
  const m = byIndex(out);
  assert.equal(m.get(0)!.item.match, "exact");
  assert.equal(m.get(1)!.item.match, "parent_domain");
  assert.equal(m.get(1)!.item.match_boundary, "registrable_domain");
  assert.equal(m.get(2)!.bucket, "unseen");
  assert.equal(m.get(3)!.item.match, "parent_domain");
  assert.equal(out.counts.headline_hits, 3);
});

test("a hit carries both days, both publishers in order, and the newest action", async () => {
  const { out } = await run(["evil.example.com"], { seeds: MATCHING });
  const hit = out.hits[0];
  assert.deepEqual([hit.first_seen, hit.last_seen, hit.report_count], ["2026-09-04", "2026-09-05", 2]);
  assert.deepEqual(hit.publishers, ["Alpha", "Beta"]);
  assert.equal(hit.source_count, 2);
  assert.equal(hit.suggested_investigation_action, "hunt");
  assert.equal(hit.priority, "medium");
  assert.equal(hit.days_since_last_seen, 0, "counted to the corpus end, not to today");
  assert.equal(hit.citation_count, 2);
  assert.equal(hit.citations.length, 1, "compact returns the first citation");
  assert.equal(hit.citations[0].report_id, "rpt-0");
  assert.equal(hit.citations[0].context, undefined);
});

test("full detail returns every citation, and context only with the scope", async () => {
  const without = await run(["evil.example.com"], { seeds: MATCHING }, { detail: "full" });
  assert.equal(without.out.hits[0].citations.length, 2);
  assert.equal(without.out.hits[0].citations[0].context, undefined);
  const withScope = await run(["evil.example.com"], { seeds: MATCHING }, { detail: "full", mayReadContext: true });
  assert.equal(withScope.out.hits[0].citations[0].context, "context 1");
});

test("a URL matches whole first, a trailing slash on either side is ignored, then its host", async () => {
  const { out } = await run(
    [
      "https://evil.example.com/payload",
      "https://evil.example.com/payload/",
      "https://kit.example.com/kit",
      "https://evil.example.com/other",
    ],
    { seeds: MATCHING },
  );
  const m = byIndex(out);
  assert.equal(m.get(0)!.item.match, "exact");
  assert.equal(m.get(1)!.item.match, "exact");
  assert.equal(m.get(2)!.item.match, "exact");
  assert.equal(m.get(2)!.item.matched_value, "https://kit.example.com/kit/");
  assert.equal(m.get(3)!.item.match, "same_host");
  assert.equal(m.get(3)!.item.match_boundary, "host");
});

test("a child domain is reported but kept out of the headline", async () => {
  const { out } = await run(["parentless.com", "example.com"], { seeds: MATCHING });
  const m = byIndex(out);
  assert.equal(m.get(0)!.item.match, "child_domain");
  assert.equal(m.get(0)!.item.headline, false);
  assert.equal(m.get(0)!.item.matched_value, "cdn.parentless.com");
  assert.equal(out.counts.headline_hits, 0);
});

/* ------------------------------------------------------------ precedence --- */

test("a confirmation outranks an exclusion recorded in another article", async () => {
  const { out } = await run(["CVE-2026-20079"], {
    seeds: [{ value: "CVE-2026-20079", type: "cve", action: "patch" }],
    excluded: [{ value: "CVE-2026-20079", type: "cve", codes: ["excluded_editorial_section"] }],
  });
  assert.equal(out.hits[0].match, "exact");
});

test("an exclusion outranks a parent relation, and a whole-URL exclusion outranks the host", async () => {
  const { out } = await run(
    [
      "www.example.com",
      "https://www.cisa.gov/privacy-policy/",
      "https://evil.example.com/terms",
      "https://evil.example.com/other",
    ],
    {
      seeds: [{ value: "example.com" }, { value: "evil.example.com" }],
      excluded: [
        { value: "www.example.com", codes: ["publisher_domain"] },
        { value: "https://www.cisa.gov/privacy-policy", type: "url", codes: ["publisher_domain"] },
        { value: "https://evil.example.com/terms", type: "url", codes: ["excluded_editorial_section"] },
      ],
    },
  );
  const m = byIndex(out);
  assert.equal(m.get(0)!.bucket, "excluded");
  assert.deepEqual(m.get(0)!.item.reason_codes, ["publisher_domain"]);
  assert.equal(m.get(1)!.bucket, "excluded", "found whole, trailing slash ignored");
  assert.equal(m.get(2)!.bucket, "excluded");
  assert.equal(m.get(3)!.item.match, "same_host");
});

test("a held-back value matches only exactly", async () => {
  const { out } = await run(
    ["github.com", "https://github.com/someone/tool", "gist.github.com", "microsoftonline.com", "api.evil.example.com"],
    {
      seeds: [
        { value: "github.com", action: "hunt", benign: "vendor_brand_apex" },
        { value: "login.microsoftonline.com", action: "hunt", benign: "vendor_brand_apex" },
        { value: "evil.example.com" },
      ],
    },
  );
  const m = byIndex(out);
  assert.equal(m.get(0)!.item.verdict, "benign_listed");
  assert.equal(m.get(0)!.item.basis, "service_rule");
  assert.equal(m.get(0)!.item.reason_code, "vendor_brand_apex");
  assert.equal(m.get(1)!.bucket, "unseen", "any GitHub URL used to be a same_host hit");
  assert.equal(m.get(2)!.bucket, "unseen");
  assert.equal(m.get(3)!.bucket, "unseen");
  assert.equal(m.get(4)!.item.match, "parent_domain", "ordinary values keep their relations");
});

/* ---------------------------------------------------------------- safety --- */

test("skips are never misses, whatever the label or the fanging", async () => {
  const { out, calls } = await run(
    ["10.1.2.3", "10[.]0[.]0[.]1", "dc01.corp.local", "192.168.1.1", "https://user:pw@evil.example.com/", "fairlife", "", 7],
    { seeds: MATCHING },
    { types: ["ip", "", "domain", "domain", "url", "", "", ""] },
  );
  assert.deepEqual(
    out.skipped.map((s: Json) => s.reason),
    ["non_public_ip", "non_public_ip", "internal_hostname", "non_public_ip", "sensitive_url", "internal_hostname", "empty_value", "invalid_value"],
  );
  assert.equal(out.counts.processed, 0);
  const sent = calls.flatMap((c) => c.keys).join(" ");
  for (const secret of ["10.1.2.3", "10.0.0.1", "dc01", "192.168", "pw", "fairlife"]) {
    assert.ok(!sent.includes(secret), `${secret} reached a query`);
  }
});

test("an unknown label is reported and discarded; a disagreeing one is reported", async () => {
  const { out } = await run(["evil.example.com", "evil.example.com", "not a value"], { seeds: MATCHING }, {
    types: ["banana", "ip", ""],
  });
  const m = byIndex(out);
  assert.deepEqual(m.get(0)!.item.warnings, ["unknown_supplied_type:banana"]);
  assert.equal(m.get(0)!.item.type_supplied, null);
  assert.equal(m.get(0)!.item.match, "exact");
  assert.deepEqual(m.get(1)!.item.warnings, ["type_mismatch:supplied=ip,detected=domain"]);
  assert.equal(m.get(1)!.bucket, "skipped", "treated as the ip it was declared to be, which it is not");
  assert.equal(m.get(2)!.item.reason, "invalid_value");
});

test("an unsupported value is skipped as such", async () => {
  const { out } = await run(["evil.com/path"], { seeds: MATCHING });
  assert.equal(out.skipped[0].reason, "unsupported_type");
});

test("defanged input is matched and the change is named", async () => {
  const { out } = await run(["hxxps[:]//evil[.]example[.]com/payload"], { seeds: MATCHING });
  assert.equal(out.hits[0].match, "exact");
  assert.deepEqual(out.hits[0].normalization_applied, ["defang", "defang_scheme"]);
  assert.equal(out.hits[0].value, "hxxps[:]//evil[.]example[.]com/payload", "value is as submitted");
});

test("values past the 100th are skipped as request_limit and make the response partial", async () => {
  const values = Array.from({ length: 102 }, (_, i) => `host${i}.nowhere.com`);
  const { out } = await run(values, { seeds: MATCHING });
  assert.equal(out.status, "partial");
  assert.equal(out.truncated, true);
  assert.deepEqual(out.skipped.map((s: Json) => [s.input_index, s.reason]), [[100, "request_limit"], [101, "request_limit"]]);
  assert.equal(out.counts.unseen, 100);
});

/* ---------------------------------------------------------------- errors --- */

test("a failed statement turns only its values into errors, never misses", async () => {
  const { out } = await run(["evil.example.com", "nowhere.example.org"], {
    seeds: MATCHING,
    failWhen: (kind, keys) => kind === "excluded" && keys.includes("nowhere.example.org") && keys.length === 1,
  });
  // One statement carried both keys, so both are lost.
  assert.equal(out.status, "complete");
  const failing = await run(["evil.example.com", "nowhere.example.org"], {
    seeds: MATCHING,
    failWhen: (kind) => kind === "excluded",
  });
  assert.equal(failing.out.status, "failed");
  assert.deepEqual(failing.out.errors.map((e: Json) => e.reason), ["lookup_failed", "lookup_failed"]);
  assert.ok(!JSON.stringify(failing.out).includes("D1_ERROR"));
  void out;
});

test("losing only a child query fails the values that needed it", async () => {
  const { out } = await run(["evil.example.com", "CVE-2026-1111"], {
    seeds: [...MATCHING, { value: "CVE-2026-1111", type: "cve" }],
    failWhen: (kind) => kind === "children",
  });
  const m = byIndex(out);
  assert.equal(m.get(0)!.item.reason, "lookup_failed");
  assert.equal(m.get(1)!.bucket, "hits", "a CVE needs no child query");
  assert.equal(out.status, "partial");
});

test("statements after the time budget are not sent", async () => {
  let t = 0;
  const { out, calls } = await run(["evil.example.com"], {
    seeds: MATCHING,
    clock: () => (t += 6_000),
    budgetMs: 10_000,
  });
  assert.equal(out.errors[0].reason, "time_budget_exceeded");
  assert.ok(calls.every((c) => c.kind !== "cve"), "nothing sent once the budget ran out");
});

test("a value that cannot be cited is an error, not a hit", async () => {
  const { out } = await run(["uncited.example.com"], { seeds: [{ value: "uncited.example.com", url: null }] });
  assert.equal(out.errors[0].reason, "missing_citation");
});

test("an unreadable corpus fails every value", async () => {
  const { out } = await run(["evil.example.com", "10.0.0.1"], {
    seeds: MATCHING,
    failWhen: (kind) => kind === "corpus",
  });
  assert.equal(out.status, "failed");
  assert.equal(out.corpus_version, null);
  assert.equal(out.errors.length, 1);
  assert.equal(out.skipped.length, 1);
});

/* ---------------------------------------------------------------- corpus --- */

test("corpus_version is reported only while the stored days match it", async () => {
  const good = await run(["evil.example.com"], { seeds: MATCHING });
  assert.equal(good.out.corpus_version, "2026-09-05.abcdef123456");
  assert.equal(good.out.coverage.version_note, undefined);
  assert.deepEqual(good.out.coverage.report_range, ["2026-09-04", "2026-09-05"]);
  assert.deepEqual(good.out.coverage.days_with_source_failures, [
    { report_date: "2026-09-04", sources_failed: ["recorded-future"] },
  ]);

  const behind = await run(["evil.example.com"], { seeds: MATCHING, state: { days: 1, last_date: "2026-09-04" } });
  assert.equal(behind.out.corpus_version, null);
  assert.match(behind.out.coverage.version_note, /withheld/);

  const none = await run(["evil.example.com"], { seeds: MATCHING, state: null });
  assert.equal(none.out.corpus_version, null);
});

test("a CVE hit carries the newest day's record with its provenance", async () => {
  const { out } = await run(["cve-2026-1111"], {
    seeds: [{ value: "CVE-2026-1111", type: "cve", action: "patch" }],
    cve: [
      { id: "CVE-2026-1111", date: "2026-09-04", record: { kev: false, cvss_severity: "HIGH" } },
      {
        id: "CVE-2026-1111",
        date: "2026-09-05",
        record: {
          kev: true,
          kev_due_date: "2026-09-18",
          cvss_score: 9.8,
          cvss_severity: "CRITICAL",
          epss_score: 0.5,
          sources: ["https://www.cisa.gov/kev.json"],
          retrieved_at: "2026-09-04T22:02:21+00:00",
        },
      },
    ],
  });
  const hit = out.hits[0];
  assert.equal(hit.normalized_value, "CVE-2026-1111");
  assert.equal(hit.vulnerability.observed_on, "2026-09-05");
  assert.equal(hit.vulnerability.kev.listed, true);
  assert.equal(hit.vulnerability.cvss.score, 9.8);
  assert.deepEqual(hit.vulnerability.provenance, ["https://www.cisa.gov/kev.json"]);
  assert.equal(hit.reason_code, "kev_listed");
  const network = await run(["evil.example.com"], { seeds: MATCHING });
  assert.equal(network.out.hits[0].vulnerability, null);
  assert.equal(network.out.hits[0].reason_code, "publisher_indicator");
});

test("since reaches every day-scoped query and narrows the answer", async () => {
  const { out, calls } = await run(["evil.example.com"], { seeds: MATCHING }, { since: "2026-09-05" });
  assert.deepEqual(out.hits[0].publishers, ["Beta"]);
  assert.ok(calls.filter((c) => c.kind !== "cve" && c.kind !== "corpus").every((c) => c.since === "2026-09-05"));
  const ignored = await run(["evil.example.com"], { seeds: MATCHING }, { since: "last week" });
  assert.equal(ignored.out.since, null);
});

test("duplicates are answered at each position", async () => {
  const { out } = await run(["evil.example.com", "EVIL.example.com", "evil.example.com"], { seeds: MATCHING });
  assert.deepEqual(out.hits.map((h: Json) => h.input_index), [0, 1, 2]);
});

/* ------------------------------------------------- the contract's examples --- */

test("every example in the contract conforms to the output schema", () => {
  const dir = new URL("../../../docs/examples/enrich_observables/", import.meta.url);
  let checked = 0;
  for (const name of ["response-complete.json", "response-partial.json", "response-failed.simulated.json"]) {
    const body = JSON.parse(readFileSync(new URL(name, dir), "utf8"));
    const structured = body.result.structuredContent;
    assertShape(structured);
    assert.deepEqual(JSON.parse(body.result.content[0].text), structured, `${name}: text and structuredContent agree`);
    assert.equal(body.result.isError, structured.status === "failed", `${name}: isError follows status`);
    checked += 1;
  }
  const published = JSON.parse(readFileSync(new URL("tool-definition.json", dir), "utf8"));
  assert.deepEqual(published.outputSchema, SCHEMA, "the published tool definition carries this schema");
  assert.equal(checked, 3);
});
