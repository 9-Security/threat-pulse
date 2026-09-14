/**
 * Run with: npm test  (node's own runner, stripping types -- no dependency)
 */
import assert from "node:assert/strict";
import test from "node:test";

import { partition } from "./guard.ts";
import { lookupAccepted, statusOf, type LookupDeps } from "./lookup.ts";

interface Row {
  value: string;
  report_date: string;
}

/** Parent candidates by label, most specific first -- enough for these tests. */
function labels(value: string): string[] {
  const parts = value.toLowerCase().split(".");
  const out: string[] = [];
  for (let i = 0; i < parts.length - 1; i += 1) out.push(parts.slice(i).join("."));
  return out.length ? out : [value.toLowerCase()];
}

function fakeDb(options: {
  rows?: Row[];
  failWhen?: (chunk: string[], call: number) => boolean;
  chunkSize?: number;
  budgetMs?: number;
  now?: () => number;
  expand?: (value: string) => string[];
}) {
  const calls: string[][] = [];
  const rows = options.rows ?? [];
  let call = 0;
  const deps: LookupDeps<Row> = {
    expand: options.expand ?? labels,
    query: async (chunk) => {
      call += 1;
      calls.push(chunk);
      if (options.failWhen?.(chunk, call)) {
        throw new Error("D1_ERROR: internal: SELECT * FROM indicators WHERE value_lc IN (secret.example)");
      }
      return rows.filter((row) => chunk.includes(row.value));
    },
    keyOf: (row) => row.value,
    toHit: (row) => ({ value: row.value, report_date: row.report_date }),
    now: options.now ?? (() => 0),
    budgetMs: options.budgetMs ?? 10_000,
    chunkSize: options.chunkSize ?? 90,
  };
  return { deps, calls };
}

test("a value is answered from its most specific candidate", async () => {
  const { deps } = fakeDb({
    rows: [
      { value: "evil.com", report_date: "2026-09-04" },
      { value: "b.evil.com", report_date: "2026-09-05" },
    ],
  });

  const result = await lookupAccepted([{ input_index: 0, value: "a.b.evil.com" }], deps);

  assert.equal(result.errors.length, 0);
  assert.equal(result.items[0].matched_on, "b.evil.com");
  assert.equal(result.items[0].exact, false);
  assert.equal(result.items[0].found, true);
  assert.deepEqual(result.items[0].seen_on, ["2026-09-05"]);
  assert.equal(statusOf(result.items.length, result.errors.length), "complete");
});

test("a miss is only a miss when every candidate was queried", async () => {
  const { deps } = fakeDb({});

  const result = await lookupAccepted([{ input_index: 3, value: "nothing.example.net" }], deps);

  assert.deepEqual(result.errors, []);
  assert.equal(result.items[0].found, false);
  assert.equal(result.items[0].input_index, 3);
});

test("a failed statement turns its values into errors, and only those", async () => {
  const identity = (value: string) => [value];
  const { deps } = fakeDb({ expand: identity, chunkSize: 2, failWhen: (_chunk, call) => call === 2 });
  const accepted = [
    { input_index: 0, value: "aaa" },
    { input_index: 1, value: "bbb" },
    { input_index: 2, value: "ccc" },
  ];

  const result = await lookupAccepted(accepted, deps);

  assert.deepEqual(result.items.map((i) => i.input_index), [0, 1]);
  assert.deepEqual(result.errors, [{ input_index: 2, value: "ccc", reason: "lookup_failed" }]);
  assert.equal(statusOf(result.items.length, result.errors.length), "partial");
  // The database's own message never reaches the response.
  assert.ok(!JSON.stringify(result).includes("D1_ERROR"));
  assert.ok(!JSON.stringify(result).includes("secret.example"));
});

test("losing the most specific candidate is an error, not a weaker match", async () => {
  const { deps } = fakeDb({
    chunkSize: 1,
    rows: [{ value: "evil.com", report_date: "2026-09-04" }],
    failWhen: (chunk) => chunk.includes("x.evil.com"),
  });

  const result = await lookupAccepted([{ input_index: 0, value: "x.evil.com" }], deps);

  assert.equal(result.items.length, 0, "must not answer from evil.com when x.evil.com was never checked");
  assert.deepEqual(result.errors, [{ input_index: 0, value: "x.evil.com", reason: "lookup_failed" }]);
});

test("every statement failing is a failed response, never a set of misses", async () => {
  const { deps } = fakeDb({ failWhen: () => true });

  const result = await lookupAccepted(
    [
      { input_index: 0, value: "a.example.com" },
      { input_index: 1, value: "b.example.com" },
    ],
    deps,
  );

  assert.equal(result.items.length, 0);
  assert.equal(result.errors.length, 2);
  assert.equal(statusOf(result.items.length, result.errors.length), "failed");
});

test("when the time budget runs out, no further statement is sent and the rest are errors", async () => {
  let clock = -6_000;
  const identity = (value: string) => [value];
  const { deps, calls } = fakeDb({
    expand: identity,
    chunkSize: 1,
    budgetMs: 10_000,
    now: () => (clock += 6_000), // 0 at the start, then 6 s, 12 s, 18 s
  });
  const accepted = [
    { input_index: 0, value: "aaa" },
    { input_index: 1, value: "bbb" },
    { input_index: 2, value: "ccc" },
  ];

  const result = await lookupAccepted(accepted, deps);

  assert.equal(calls.length, 1, "statements after the budget must not be sent");
  assert.equal(result.queries, 1);
  assert.deepEqual(result.items.map((i) => i.input_index), [0]);
  assert.deepEqual(
    result.errors.map((e) => [e.input_index, e.reason]),
    [
      [1, "time_budget_exceeded"],
      [2, "time_budget_exceeded"],
    ],
  );
});

test("nothing accepted sends nothing and is complete", async () => {
  const { deps, calls } = fakeDb({});

  const result = await lookupAccepted([], deps);

  assert.equal(calls.length, 0);
  assert.equal(statusOf(result.items.length, result.errors.length), "complete");
});

test("composed with the guard, a private address or internal name never reaches a statement", async () => {
  const { deps, calls } = fakeDb({});
  const split = partition(["10.0.0.1", "evil.com", "dc01.corp", "https://user:pw@evil.com/"]);

  const result = await lookupAccepted(split.accepted, deps);

  const sent = calls.flat();
  for (const secret of ["10.0.0.1", "dc01.corp", "corp", "user", "pw"]) {
    assert.ok(!sent.some((c) => c.includes(secret)), `${secret} reached a statement`);
  }
  assert.deepEqual(result.items.map((i) => i.input_index), [1]);
  assert.deepEqual(split.skipped.map((s) => s.reason), ["non_public_ip", "internal_hostname", "sensitive_url"]);
});

test("status is decided by errors, not by skips", () => {
  assert.equal(statusOf(3, 0), "complete");
  assert.equal(statusOf(0, 0), "complete");
  assert.equal(statusOf(2, 1), "partial");
  assert.equal(statusOf(0, 3), "failed");
});
