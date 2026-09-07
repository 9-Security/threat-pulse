from soc_news_parser.publicsuffix import (
    is_public_suffix,
    public_suffix,
    public_suffix_list_version,
    registrable_domain,
)


def test_ordinary_domains_split_at_the_tld() -> None:
    assert public_suffix("sub.example.com") == "com"
    assert registrable_domain("sub.example.com") == "example.com"
    assert registrable_domain("example.com") == "example.com"


def test_multi_label_suffixes_are_not_registrable() -> None:
    """`co.uk` is a registry, so the organisation is one label further left."""
    assert public_suffix("a.b.evil.co.uk") == "co.uk"
    assert registrable_domain("a.b.evil.co.uk") == "evil.co.uk"
    assert registrable_domain("co.uk") == ""
    assert is_public_suffix("co.uk")


def test_platform_suffixes_the_label_heuristic_missed() -> None:
    """Six- and seven-character left labels, which a "short apex" rule lets by.

    Each of these owns nothing itself; the tenant one label to the left does.
    """
    for suffix in ("github.io", "gitlab.io", "duckdns.org", "it.com"):
        assert is_public_suffix(suffix), suffix
        assert registrable_domain(suffix) == ""
    assert registrable_domain("evil.github.io") == "evil.github.io"
    assert registrable_domain("m-doxa-geo.duckdns.org") == "m-doxa-geo.duckdns.org"


def test_a_name_that_only_looks_like_a_platform() -> None:
    """`squarespace.com` reads like a boundary but is an ordinary domain."""
    assert not is_public_suffix("squarespace.com")
    assert registrable_domain("www.squarespace.com") == "squarespace.com"


def test_wildcard_and_exception_rules() -> None:
    """`*.ck` with `!www.ck` -- the exception has to beat the wildcard."""
    assert is_public_suffix("foo.ck")
    assert public_suffix("www.ck") == "ck"
    assert registrable_domain("www.ck") == "www.ck"


def test_unknown_tld_is_treated_as_one_label() -> None:
    """An unlisted TLD falls back to the implicit `*` rule.

    Without it a novel TLD would look like it had no suffix at all, and the
    whole host would read as registrable.
    """
    assert public_suffix("some.brand-new-tld-xyz") == "brand-new-tld-xyz"
    assert registrable_domain("some.brand-new-tld-xyz") == "some.brand-new-tld-xyz"


def test_input_is_normalised() -> None:
    assert public_suffix("SUB.Example.COM.") == "com"
    assert registrable_domain("  sub.example.com  ") == "example.com"


def test_a_bare_tld_owns_nothing() -> None:
    assert is_public_suffix("com")
    assert registrable_domain("com") == ""


def test_version_reflects_the_bundled_list() -> None:
    version = public_suffix_list_version()
    assert version.startswith("psl-")
    assert version == public_suffix_list_version()
