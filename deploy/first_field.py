"""Read one field out of a `wrangler d1 execute --json` result on stdin.

Wrangler wraps the rows in a report object and prints npm noise around it, so a
shell pipeline cannot reach the value without a JSON parser.

Prints nothing when the query matched no rows, and also when the output could
not be parsed at all. Both mean the caller cannot compare against a stored
value, so a guard reading this fails open -- it behaves as it did before the
guard existed rather than blocking a push on a transient wrangler error.

    wrangler d1 execute ... --json | python3 first_field.py article_count
"""

from __future__ import annotations

import json
import re
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: first_field.py FIELD", file=sys.stderr)
        return 2
    field = sys.argv[1]
    # The JSON array is preceded by warnings and followed by npm notices.
    match = re.search(r"\[.*\]", sys.stdin.read(), re.S)
    if not match:
        return 0
    try:
        rows = json.loads(match.group())[0]["results"]
    except (ValueError, KeyError, IndexError):
        return 0
    if rows and field in rows[0]:
        print(rows[0][field])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
