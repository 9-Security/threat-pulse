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

from functools import lru_cache
from importlib import resources


__all__ = [
    "public_suffix",
    "registrable_domain",
    "is_public_suffix",
    "public_suffix_list_version",
]


def _load_rules() -> tuple[frozenset[str], frozenset[str], frozenset[str]]:
    """Split the list into normal, wildcard and exception rules.

    Wildcard rules are stored by their parent (`*.ck` as `ck`) and exception
    rules without the `!`, which is how both are matched below.
    """
    text = (
        resources.files(__package__)
        .joinpath("data/public_suffix_list.dat")
        .read_text(encoding="utf-8")
    )
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
    return frozenset(normal), frozenset(wildcard), frozenset(exception)


NORMAL_RULES, WILDCARD_RULES, EXCEPTION_RULES = _load_rules()


def public_suffix_list_version() -> str:
    """Rule counts, for reporting which list produced a boundary."""
    return (
        f"psl-{len(NORMAL_RULES)}n-{len(WILDCARD_RULES)}w-{len(EXCEPTION_RULES)}x"
    )


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
