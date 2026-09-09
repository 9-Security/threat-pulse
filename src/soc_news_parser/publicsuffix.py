"""Public Suffix List lookups for domain boundary decisions.

Where a hostname stops being an organisation and starts being a registry is not
something label counting can answer. `github.io` and `it.com` are public
suffixes; blocking either takes out every unrelated tenant beneath it, and both
survive a "short parent" heuristic -- `github.io` has a six-character left
label. `squarespace.com`, which reads like a platform, is an ordinary
registrable domain.

The list is bundled with the package and never fetched at runtime, so the same
body always yields the same boundary, exactly as the IANA TLD list works.
Refresh it with:

    curl -s https://publicsuffix.org/list/public_suffix_list.dat \
      > src/soc_news_parser/data/public_suffix_list.dat
"""

from __future__ import annotations

import hashlib
from functools import lru_cache
from importlib import resources


__all__ = [
    "public_suffix",
    "registrable_domain",
    "is_public_suffix",
    "public_suffix_list_version",
]


# The real list carries around ten thousand rules. A truncated or empty file
# would parse without complaint and quietly answer "not a public suffix" to
# everything, putting `github.io` back on block lists with nothing logged, so a
# floor is enforced at import: a boundary list that cannot decide boundaries is
# a failure to start, not a default.
MINIMUM_RULES = 1000

_LIST_PATH = "data/public_suffix_list.dat"


def _read_list() -> str:
    return (
        resources.files(__package__).joinpath(_LIST_PATH).read_text(encoding="utf-8")
    )


def _load_rules(text: str) -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """Split the list into normal, wildcard and exception rules.

    Wildcard rules are stored by their parent (`*.ck` as `ck`) and exception
    rules without the `!`, which is how both are matched below.
    """
    normal: set[str] = set()
    wildcard: set[str] = set()
    exception: set[str] = set()
    for line in text.splitlines():
        rule = line.strip()
        if not rule or rule.startswith("//"):
            continue
        if rule.startswith("!"):
            exception.add(rule[1:].lower())
        elif rule.startswith("*."):
            wildcard.add(rule[2:].lower())
        else:
            normal.add(rule.lower())
    if len(normal) < MINIMUM_RULES:
        raise RuntimeError(
            f"{_LIST_PATH} yielded {len(normal)} rules, expected at least "
            f"{MINIMUM_RULES}. Refresh it from https://publicsuffix.org/list/ "
            "-- a short list silently disables every boundary decision."
        )
    return frozenset(normal), frozenset(wildcard), frozenset(exception)


NORMAL_RULES, WILDCARD_RULES, EXCEPTION_RULES = _load_rules(_read_list())
# Over the parsed rules, not the file. Counting rules misses a refresh that adds
# one suffix and drops another -- every count identical, a real domain moved
# across the block/hunt line. Hashing the file text overshoots the other way: an
# edited comment or a CRLF checkout changes the digest while no boundary moves.
# Callers derive a version to learn when a decision could have changed, and only
# the rule sets decide anything.
_RULES_DIGEST = hashlib.sha256(
    "\n".join(
        [
            "N",
            *sorted(NORMAL_RULES),
            "W",
            *sorted(WILDCARD_RULES),
            "X",
            *sorted(EXCEPTION_RULES),
        ]
    ).encode("utf-8")
).hexdigest()[:12]


def public_suffix_list_version() -> str:
    """A digest of the parsed rules, identifying which list drew a boundary.

    Changes when, and only when, a boundary decision could change: comments,
    ordering and line endings are all absent from what is hashed.

    One exception, and it is behind us: on 2026-09-09 the input changed from the
    rule counts to the rules themselves, so the string moved once without any
    boundary moving. A version compared across that date is not evidence the
    list changed.
    """
    return f"psl-{_RULES_DIGEST}"


def _labels(host: str) -> list[str]:
    return host.strip().strip(".").lower().split(".")


@lru_cache(maxsize=4096)
def public_suffix(host: str) -> str:
    """The registry-controlled tail of `host`.

    Follows the matching algorithm from publicsuffix.org: the prevailing rule is
    the one matching the most labels, an exception rule wins over a wildcard
    covering the same name, and an unlisted TLD falls back to the implicit `*`
    rule -- so an unknown suffix is treated as one label rather than as nothing,
    which keeps a novel TLD from making the whole host look registrable.
    """
    labels = _labels(host)
    if not labels or not labels[-1]:
        return ""
    for index in range(len(labels)):
        candidate = ".".join(labels[index:])
        if candidate in EXCEPTION_RULES:
            # The rule names the exception; the suffix is what remains above it.
            return ".".join(labels[index + 1 :])
        parent = ".".join(labels[index + 1 :])
        if parent and parent in WILDCARD_RULES:
            return candidate
        if candidate in NORMAL_RULES:
            return candidate
    return labels[-1]


def is_public_suffix(host: str) -> bool:
    """True when `host` is the boundary itself and owns nothing below it."""
    normalized = ".".join(_labels(host))
    return bool(normalized) and public_suffix(normalized) == normalized


@lru_cache(maxsize=4096)
def registrable_domain(host: str) -> str:
    """The public suffix plus the one label an organisation actually registers.

    Empty when `host` is a public suffix, because nothing there belongs to
    anyone in particular.
    """
    labels = _labels(host)
    suffix = public_suffix(host)
    if not suffix:
        return ""
    suffix_length = len(suffix.split("."))
    if len(labels) <= suffix_length:
        return ""
    return ".".join(labels[-(suffix_length + 1) :])
