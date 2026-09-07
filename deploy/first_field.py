"""Read fields out of the JSON a CLI printed, for a shell script to compare.

Two shapes, because two callers need one:

    wrangler d1 execute ... --json | first_field.py article_count ...
    printf '%s' "$deliver_output" | first_field.py --plain json_output

Wrangler wraps rows in a report object and npm decorates the stream around it,
so the array has to be found rather than parsed from position 0. `--plain`
reads a single JSON object, which is what the parser's own commands print.

Exit status carries the distinction a guard depends on:

    0 with output     the value was read
    0 with no output  the query ran and matched nothing
    1                 the output could not be parsed at all

Without that split, a caller cannot tell "no row stored yet" from "wrangler
never answered", and an expired token reads as an empty database.
"""

from __future__ import annotations

import json
import re
import sys


def _find_wrangler_rows(text: str) -> list[dict[str, object]] | None:
    """The first JSON array in the stream that parses as wrangler's envelope.

    Scanning for a bracket and taking everything to the last one would swallow
    any bracketed banner printed alongside it, so each candidate start is parsed
    with a decoder that stops at the end of its own value.
    """
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\[", text):
        try:
            value, _ = decoder.raw_decode(text[match.start() :])
        except ValueError:
            continue
        if not isinstance(value, list) or not value:
            continue
        first = value[0]
        if isinstance(first, dict) and isinstance(first.get("results"), list):
            return [row for row in first["results"] if isinstance(row, dict)]
    return None


def main(argv: list[str]) -> int:
    plain = False
    if argv and argv[0] == "--plain":
        plain = True
        argv = argv[1:]
    if not argv:
        print("usage: first_field.py [--plain] FIELD [FIELD ...]", file=sys.stderr)
        return 2

    text = sys.stdin.read()
    if plain:
        try:
            row: dict[str, object] | None = json.loads(text)
        except ValueError:
            print("could not parse JSON on stdin", file=sys.stderr)
            return 1
        if not isinstance(row, dict):
            print("expected a JSON object on stdin", file=sys.stderr)
            return 1
        rows = [row]
    else:
        found = _find_wrangler_rows(text)
        if found is None:
            print("could not find a wrangler result array on stdin", file=sys.stderr)
            return 1
        rows = found

    if not rows:
        return 0  # Ran fine, matched nothing.
    values = [rows[0].get(field) for field in argv]
    if any(value is None for value in values):
        missing = [f for f, v in zip(argv, values) if v is None]
        print(f"field(s) absent from the result: {', '.join(missing)}", file=sys.stderr)
        return 1
    print(" ".join(str(value) for value in values))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
