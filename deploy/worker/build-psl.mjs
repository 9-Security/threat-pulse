// Generates src/psl.json from the list the Python package already bundles, so
// the boundary the report was written against and the boundary a query is
// matched against can never drift apart. Run `npm run psl` after refreshing
// ../../src/soc_news_parser/data/public_suffix_list.dat.
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const source = join(here, "..", "..", "src", "soc_news_parser", "data", "public_suffix_list.dat");
const target = join(here, "src", "psl.json");

const normal = [];
const wildcard = [];
const exception = [];

for (const line of readFileSync(source, "utf8").split("\n")) {
  const rule = line.trim().toLowerCase();
  if (!rule || rule.startsWith("//")) continue;
  if (rule.startsWith("!")) exception.push(rule.slice(1));
  else if (rule.startsWith("*.")) wildcard.push(rule.slice(2));
  else normal.push(rule);
}

writeFileSync(target, JSON.stringify({ normal, wildcard, exception }));
console.log(
  `psl.json: ${normal.length} normal, ${wildcard.length} wildcard, ${exception.length} exception`,
);
