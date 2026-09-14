/**
 * The rules that decide what a lookup call returns, with the database injected.
 *
 * The review's hard requirement is that a lookup which did not happen is never
 * reported as not found. A value is therefore an item only if every candidate it
 * expands to was actually queried. When a statement throws, or the wall-clock budget
 * runs out before a statement is sent, every value with a candidate in it becomes an
 * error. That includes a value whose most specific candidate was lost while a less
 * specific one succeeded: "the most specific match wins" would otherwise quietly
 * return the weaker match as if it were the answer.
 *
 * Free of imports and Worker types, like guard.ts and heartbeat.ts, so these rules
 * are exercised under plain node against a fake database instead of being asserted
 * only in prose.
 */

export interface AcceptedValue {
  input_index: number;
  value: string;
}

export type LookupErrorReason = "lookup_failed" | "time_budget_exceeded";

export interface LookupError {
  input_index: number;
  value: string;
  reason: LookupErrorReason;
}

export type Item = Record<string, unknown>;

export interface LookupDeps<Row> {
  /** Candidates for one value, most specific first. */
  expand(value: string): string[];
  /** Run one statement for these candidates. May throw. */
  query(candidates: string[]): Promise<Row[]>;
  /** The lowercased stored value a row matched on. */
  keyOf(row: Row): string;
  toHit(row: Row): Item;
  now(): number;
  budgetMs: number;
  chunkSize: number;
}

export interface LookupResult {
  items: Item[];
  errors: LookupError[];
  /** Statements actually sent, for tests and for anyone reasoning about cost. */
  queries: number;
}

export function statusOf(items: number, errors: number): "complete" | "partial" | "failed" {
  if (errors === 0) return "complete";
  return items === 0 ? "failed" : "partial";
}

export async function lookupAccepted<Row>(
  accepted: AcceptedValue[],
  deps: LookupDeps<Row>,
): Promise<LookupResult> {
  const started = deps.now();

  const expanded = new Map<number, string[]>();
  const all = new Set<string>();
  for (const { input_index, value } of accepted) {
    const list = deps.expand(value);
    expanded.set(input_index, list);
    list.forEach((candidate) => all.add(candidate));
  }

  const rowsByKey = new Map<string, Row[]>();
  const queried = new Set<string>();
  const lost = new Map<string, LookupErrorReason>();
  const candidates = [...all];
  let queries = 0;
  for (let start = 0; start < candidates.length; start += deps.chunkSize) {
    const chunk = candidates.slice(start, start + deps.chunkSize);
    // Checked before each statement, so a call can overrun the budget by at most
    // the one statement already in flight.
    if (deps.now() - started > deps.budgetMs) {
      chunk.forEach((candidate) => lost.set(candidate, "time_budget_exceeded"));
      continue;
    }
    queries += 1;
    try {
      const rows = await deps.query(chunk);
      chunk.forEach((candidate) => queried.add(candidate));
      for (const row of rows) {
        const key = deps.keyOf(row);
        const bucket = rowsByKey.get(key);
        if (bucket) bucket.push(row);
        else rowsByKey.set(key, [row]);
      }
    } catch {
      // Recorded per value. The error itself is neither returned nor logged: it is
      // not the caller's to read, and a log line is a place a value could end up.
      chunk.forEach((candidate) => lost.set(candidate, "lookup_failed"));
    }
  }

  const items: Item[] = [];
  const errors: LookupError[] = [];
  for (const { input_index, value } of accepted) {
    const list = expanded.get(input_index) ?? [];
    const missing = list.find((candidate) => !queried.has(candidate));
    if (missing !== undefined) {
      errors.push({ input_index, value, reason: lost.get(missing) ?? "lookup_failed" });
      continue;
    }
    let matchedOn: string | null = null;
    let hits: Item[] = [];
    for (const candidate of list) {
      const rows = rowsByKey.get(candidate);
      if (rows && rows.length) {
        matchedOn = candidate;
        hits = rows.map((row) => deps.toHit(row));
        break; // the most specific match wins
      }
    }
    const dates = [...new Set(hits.map((hit) => String(hit.report_date)))].sort();
    items.push({
      input_index,
      value,
      found: hits.length > 0,
      matched_on: matchedOn,
      exact: matchedOn !== null && matchedOn === value.toLowerCase(),
      first_seen: dates[0] ?? null,
      last_seen: dates[dates.length - 1] ?? null,
      seen_on: dates,
      hits,
    });
  }
  return { items, errors, queries };
}
