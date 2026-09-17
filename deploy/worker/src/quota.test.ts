/**
 * Run with: npm test  (node's own runner, stripping types -- no dependency)
 */
import assert from "node:assert/strict";
import test from "node:test";

import {
  buckets,
  checkQuota,
  DEFAULT_PER_DAY,
  DEFAULT_PER_MINUTE,
  limitsFor,
  renderUsageAlert,
  secondsToNextUtcDay,
  type QuotaStore,
} from "./quota.ts";

/** Mirrors the D1 upsert: a row starts at 1, and never passes its limit. */
function fakeStore() {
  const counts = new Map<string, number>();
  const rejected = new Map<string, number>();
  const store: QuotaStore = {
    async take(bucket, limit) {
      const current = counts.get(bucket);
      if (current === undefined) {
        counts.set(bucket, 1);
        return true;
      }
      if (current >= limit) return false;
      counts.set(bucket, current + 1);
      return true;
    },
    async reject(day) {
      rejected.set(day, (rejected.get(day) ?? 0) + 1);
    },
  };
  return { store, counts, rejected };
}

const at = (iso: string) => new Date(iso);

test("buckets are UTC minute and day keys", () => {
  assert.deepEqual(buckets(at("2026-09-17T23:59:59.900Z")), { minute: "m:2026-09-17T23:59", day: "d:2026-09-17" });
  // Taipei is already on the 18th here; the quota day is UTC and says so in the docs.
  assert.deepEqual(buckets(at("2026-09-17T16:30:00Z")).day, "d:2026-09-17");
});

test("calls within both limits are allowed and counted", async () => {
  const { store, counts } = fakeStore();
  const now = at("2026-09-17T10:31:07Z");
  for (let i = 0; i < 3; i += 1) {
    assert.deepEqual(await checkQuota(store, { perMinute: 3, perDay: 10 }, now), { allowed: true });
  }
  assert.equal(counts.get("m:2026-09-17T10:31"), 3);
  assert.equal(counts.get("d:2026-09-17"), 3);
});

test("the call past the per-minute limit is refused, with seconds to the next minute", async () => {
  const { store, counts, rejected } = fakeStore();
  const now = at("2026-09-17T10:31:07Z");
  const limits = { perMinute: 2, perDay: 100 };
  await checkQuota(store, limits, now);
  await checkQuota(store, limits, now);

  const refused = await checkQuota(store, limits, now);

  assert.deepEqual(refused, { allowed: false, scope: "minute", limit: 2, retryAfterSeconds: 53 });
  assert.equal(counts.get("m:2026-09-17T10:31"), 2, "the minute counter never passes its limit");
  assert.equal(counts.get("d:2026-09-17"), 2, "a call refused per minute does not spend the daily quota");
  assert.equal(rejected.get("d:2026-09-17"), 1);
});

test("the next minute starts a fresh count", async () => {
  const { store } = fakeStore();
  const limits = { perMinute: 1, perDay: 100 };
  assert.equal((await checkQuota(store, limits, at("2026-09-17T10:31:59Z"))).allowed, true);
  assert.equal((await checkQuota(store, limits, at("2026-09-17T10:31:59Z"))).allowed, false);
  assert.equal((await checkQuota(store, limits, at("2026-09-17T10:32:00Z"))).allowed, true);
});

test("the call past the daily limit is refused until the next UTC day", async () => {
  const { store, counts, rejected } = fakeStore();
  const limits = { perMinute: 100, perDay: 2 };
  await checkQuota(store, limits, at("2026-09-17T10:00:00Z"));
  await checkQuota(store, limits, at("2026-09-17T11:00:00Z"));

  const refused = await checkQuota(store, limits, at("2026-09-17T23:59:30Z"));

  assert.deepEqual(refused, { allowed: false, scope: "day", limit: 2, retryAfterSeconds: 30 });
  assert.equal(counts.get("d:2026-09-17"), 2);
  assert.equal(rejected.get("d:2026-09-17"), 1);
  assert.equal((await checkQuota(store, limits, at("2026-09-18T00:00:00Z"))).allowed, true);
});

test("a limit of zero suspends a token even on its first call", async () => {
  const { store, counts } = fakeStore();
  const now = at("2026-09-17T10:00:00Z");
  assert.equal((await checkQuota(store, { perMinute: 0, perDay: 100 }, now)).allowed, false);
  const day = await checkQuota(store, { perMinute: 10, perDay: 0 }, now);
  assert.equal(day.allowed, false);
  assert.equal(day.allowed === false && day.scope, "day");
  assert.equal(counts.get("d:2026-09-17"), undefined, "nothing is counted for a suspended token");
});

test("a failing store propagates, so the caller can refuse explicitly", async () => {
  const store: QuotaStore = {
    take: async () => {
      throw new Error("D1 unavailable");
    },
    reject: async () => {},
  };
  await assert.rejects(checkQuota(store, { perMinute: 1, perDay: 1 }, new Date()));
});

test("limits fall back to the defaults unless the row sets a whole number", () => {
  assert.deepEqual(limitsFor({}), { perMinute: DEFAULT_PER_MINUTE, perDay: DEFAULT_PER_DAY });
  assert.deepEqual(limitsFor({ rate_per_minute: null, rate_per_day: null }), {
    perMinute: DEFAULT_PER_MINUTE,
    perDay: DEFAULT_PER_DAY,
  });
  assert.deepEqual(limitsFor({ rate_per_minute: 5, rate_per_day: 0 }), { perMinute: 5, perDay: 0 });
  assert.deepEqual(limitsFor({ rate_per_minute: -1, rate_per_day: 2.5 }), {
    perMinute: DEFAULT_PER_MINUTE,
    perDay: DEFAULT_PER_DAY,
  });
});

test("seconds to the next UTC day are never zero", () => {
  assert.equal(secondsToNextUtcDay(at("2026-09-17T00:00:00Z")), 86_400);
  assert.equal(secondsToNextUtcDay(at("2026-09-17T23:59:59.999Z")), 1);
});

test("a quiet day sends no usage mail", () => {
  assert.equal(renderUsageAlert("2026-09-17", []), null);
  assert.equal(renderUsageAlert("2026-09-17", [{ label: "mssp", calls: 100, rejected: 0, perDay: 5000 }]), null);
});

test("refusals and heavy use are reported, by label only", () => {
  const mail = renderUsageAlert("2026-09-17", [
    { label: "mssp pilot", calls: 4000, rejected: 0, perDay: 5000 },
    { label: "analyst", calls: 12, rejected: 3, perDay: 5000 },
    { label: "quiet", calls: 1, rejected: 0, perDay: 5000 },
  ]);
  assert.ok(mail);
  assert.match(mail.subject, /2026-09-17 UTC/);
  assert.match(mail.body, /mssp pilot: 4000 of 5000 calls; 80% of its daily quota used/);
  assert.match(mail.body, /analyst: 12 of 5000 calls; 3 call\(s\) refused by quota/);
  assert.doesNotMatch(mail.body, /quiet/);
});
