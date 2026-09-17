/**
 * Per-token call quotas: a per-minute and a per-day ceiling on `tools/call` and on
 * the heartbeat probe.
 *
 * Counters live in D1, keyed by token hash and a UTC time bucket, and each is taken
 * with a single conditional upsert, so a counter never passes its limit even under
 * concurrent calls. A call refused here is refused before its values are read, so
 * nothing about it is looked up. The refusal is recorded on the day's row, so the
 * daily usage check can see a caller being turned away.
 *
 * Free of imports and Worker types, like guard.ts and lookup.ts, so the rules are
 * tested under plain node against a fake store.
 */

export const DEFAULT_PER_MINUTE = 60;
export const DEFAULT_PER_DAY = 5_000;
/** Day rows are kept this long for usage history; minute rows only until the next check. */
export const USAGE_RETENTION_DAYS = 90;
/** Share of the daily quota at which the usage check reports a token. */
export const USAGE_ALERT_SHARE = 0.8;

export interface QuotaLimits {
  perMinute: number;
  perDay: number;
}

export type QuotaScope = "minute" | "day";

export type QuotaDecision =
  | { allowed: true }
  | { allowed: false; scope: QuotaScope; limit: number; retryAfterSeconds: number };

export interface QuotaStore {
  /**
   * Add one to the bucket if it is below `limit`, atomically. True when counted;
   * false when the bucket was already at the limit and nothing changed.
   */
  take(bucket: string, limit: number): Promise<boolean>;
  /** Record a refused call on the given day bucket. */
  reject(dayBucket: string): Promise<void>;
}

/** NULL or a non-integer in the token row means "use the default". */
export function limitsFor(row: { rate_per_minute?: unknown; rate_per_day?: unknown }): QuotaLimits {
  const pick = (value: unknown, fallback: number) =>
    typeof value === "number" && Number.isInteger(value) && value >= 0 ? value : fallback;
  return {
    perMinute: pick(row.rate_per_minute, DEFAULT_PER_MINUTE),
    perDay: pick(row.rate_per_day, DEFAULT_PER_DAY),
  };
}

/** UTC buckets. `m:` rows sort before `d:` rows and within each kind by time. */
export function buckets(now: Date): { minute: string; day: string } {
  const iso = now.toISOString(); // 2026-09-17T10:31:07.123Z
  return { minute: `m:${iso.slice(0, 16)}`, day: `d:${iso.slice(0, 10)}` };
}

export function secondsToNextMinute(now: Date): number {
  return 60 - now.getUTCSeconds();
}

export function secondsToNextUtcDay(now: Date): number {
  const next = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1);
  return Math.max(1, Math.ceil((next - now.getTime()) / 1000));
}

export async function checkQuota(store: QuotaStore, limits: QuotaLimits, now: Date): Promise<QuotaDecision> {
  const { minute, day } = buckets(now);

  // A limit of 0 suspends a token without revoking it. The store cannot express
  // that on its own: the first call of a bucket inserts a row at 1.
  if (limits.perMinute <= 0 || !(await store.take(minute, limits.perMinute))) {
    await store.reject(day);
    return { allowed: false, scope: "minute", limit: limits.perMinute, retryAfterSeconds: secondsToNextMinute(now) };
  }
  if (limits.perDay <= 0 || !(await store.take(day, limits.perDay))) {
    await store.reject(day);
    return { allowed: false, scope: "day", limit: limits.perDay, retryAfterSeconds: secondsToNextUtcDay(now) };
  }
  return { allowed: true };
}

export interface DayUsage {
  label: string;
  calls: number;
  rejected: number;
  perDay: number;
}

/**
 * What the daily usage check reports: any refusal, and any token that used most of
 * its day. Returns null when there is nothing to say, so a quiet day sends nothing.
 */
export function renderUsageAlert(day: string, usage: DayUsage[]): { subject: string; body: string } | null {
  const heavy = (u: DayUsage) => u.perDay > 0 && u.calls >= u.perDay * USAGE_ALERT_SHARE;
  const notable = usage.filter((u) => u.rejected > 0 || heavy(u));
  if (!notable.length) return null;
  const lines = notable.map((u) => {
    const notes: string[] = [];
    if (u.rejected > 0) notes.push(`${u.rejected} call(s) refused by quota`);
    if (heavy(u)) notes.push(`${Math.round((u.calls / u.perDay) * 100)}% of its daily quota used`);
    return `- ${u.label}: ${u.calls} of ${u.perDay} calls; ${notes.join("; ")}`;
  });
  return {
    subject: `[threat-pulse] token usage needs a look (${day} UTC)`,
    body: [
      `Client token usage on ${day} (UTC) that crossed a reporting threshold:`,
      "",
      ...lines,
      "",
      "A refusal means a client hit its per-minute or per-day quota. Sustained use near",
      "the quota, or use by a token that should be idle, is a reason to check with the",
      "client and, if the token may have leaked, to revoke it:",
      "  node token-admin.mjs revoke <label>",
    ].join("\n"),
  };
}
