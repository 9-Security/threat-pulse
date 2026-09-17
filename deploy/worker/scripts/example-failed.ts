/**
 * Writes the contract's `failed` example: every database statement throws.
 *
 *   node --experimental-strip-types scripts/example-failed.ts > ../../docs/examples/enrich_observables/response-failed.simulated.json
 *
 * A real `failed` response needs the database to be unreachable, which is not
 * something to cause in production for a document. The rules that produce this
 * response are the ones the service runs.
 */
import { enrichObservables, type EnrichStore } from "../src/enrich.ts";

const down = async (): Promise<never> => {
  throw new Error("D1_ERROR: simulated outage");
};
const store: EnrichStore = {
  indicators: down,
  children: down,
  excluded: down,
  cveIntel: down,
  corpus: async () => ({
    state: {
      corpus_version: "2026-09-17.478eee3d0883",
      days: 14,
      first_date: "2026-09-04",
      last_date: "2026-09-17",
      publisher_count: 18,
      psl_version: "psl-6048303ea5bc",
    },
    reports: Array.from({ length: 14 }, (_, i) => {
      const day = `2026-09-${String(4 + i).padStart(2, "0")}`;
      return { report_date: day, report_id: `(report id of ${day})`, sources_failed: "[]" };
    }),
  }),
};

const structured = await enrichObservables(
  { values: ["CVE-2026-20079", "login.service-nowinc[.]com", "10.0.0.5"], mayReadContext: false },
  {
    store,
    boundaries: {
      // A one-label suffix is enough for the values above.
      parents: (host) => {
        const labels = host.split(".");
        const out: string[] = [];
        for (let i = 1; i < labels.length - 1; i += 1) out.push(labels.slice(i).join("."));
        return out;
      },
      registrable: (host) => host.split(".").slice(-2).join("."),
    },
    now: () => Date.parse("2026-09-18T01:00:00Z"),
    requestId: () => "00000000-0000-4000-8000-000000000000",
    budgetMs: 10_000,
    chunkSize: 90,
  },
);

const envelope = {
  jsonrpc: "2.0",
  id: 107,
  result: {
    content: [{ type: "text", text: JSON.stringify(structured, null, 2) }],
    structuredContent: structured,
    isError: true,
  },
};
process.stdout.write(`${JSON.stringify(envelope, null, 2)}\n`);
