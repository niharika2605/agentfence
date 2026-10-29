"""Tests for the host, URL and email canonicalizers (Day 10)."""
import string

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from agentfence.canon.errors import CanonicalizationError, block_for
from agentfence.canon.urls import (
    CanonicalHost,
    canonicalize_email,
    canonicalize_host,
    canonicalize_url,
    is_allowed_domain,
    registered_domain,
)
from agentfence.models import Effect, ReasonCode

CYRILLIC_A = "\u0430"
FULLWIDTH_E = "\uff45"
IDEOGRAPHIC_DOT = "\u3002"
FULLWIDTH_AT = "\uff20"


def host(raw: str, *, allow_ip: bool = False) -> CanonicalHost:
    return canonicalize_host(raw, allow_ip=allow_ip)


def host_denied(raw: object, *, allow_ip: bool = False) -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize_host(raw, allow_ip=allow_ip)


def url_denied(raw: object) -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize_url(raw)


def email_denied(raw: object) -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize_email(raw)


# ---------- registered domain ----------

@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("example.com", "example.com"),
        ("a.b.example.com", "example.com"),
        ("example.co.in", "example.co.in"),
        ("a.b.co.uk", "b.co.uk"),
        ("co.uk", None),
        ("evil.github.io", "evil.github.io"),
        ("github.io", None),
        ("x.s3.amazonaws.com", "x.s3.amazonaws.com"),
        ("s3.amazonaws.com", None),
        ("com", None),
    ],
)
def test_registered_domain(name: str, expected: str | None) -> None:
    assert registered_domain(name) == expected


# ---------- hosts ----------

def test_host_is_lowercased_and_trailing_dot_removed() -> None:
    assert host("Example.COM.").name == "example.com"


def test_host_registered_domain_for_subdomains() -> None:
    assert host("mail.company.com").registered_domain == "company.com"
    assert host("a.b.co.uk").registered_domain == "b.co.uk"


def test_international_names_become_punycode() -> None:
    result = host("b\u00fccher.example")
    assert result.name == "xn--bcher-kva.example"
    assert result.is_idn


def test_fullwidth_letters_and_dots_map_to_the_real_destination() -> None:
    assert host(f"{FULLWIDTH_E}xample{IDEOGRAPHIC_DOT}com").name == "example.com"


def test_mixed_alphabets_are_denied() -> None:
    host_denied(f"{CYRILLIC_A}pple.com")
    host_denied("xn--pple-43d.com")
    host_denied("\u03bfn.com")


def test_all_cyrillic_name_is_allowed_but_marked_international_and_never_matches() -> None:
    lookalike = host("\u0430\u0440\u0440\u04cf\u0435.com")
    assert lookalike.is_idn
    assert lookalike.name.startswith("xn--")
    assert not is_allowed_domain(lookalike, ["apple.com"])


@pytest.mark.parametrize(
    "raw",
    [
        "", "   ", None, 5, b"example.com", "a b.com", "exa\x00mple.com", "exa\tmple.com",
        "-bad.com", "bad-.com", "a..com", ".com", "com", "a_b.com", "exa$mple.com",
        "xn--.com", "xn--a.com", "xn--zzzzzzzz.com", "a" * 64 + ".com",
        ("a" * 60 + ".") * 5 + "com", "exa\\mple.com", "example.com..",
    ],
)
def test_bad_hosts_are_denied(raw: object) -> None:
    host_denied(raw)


@pytest.mark.parametrize(
    "raw",
    ["localhost", "foo.localhost", "printer.local", "db.internal", "x.corp", "nas.lan",
     "router.home.arpa", "intranet", "1.0.0.127.in-addr.arpa"],
)
def test_local_and_internal_names_are_denied(raw: str) -> None:
    host_denied(raw)


# ---------- address hosts ----------

def test_addresses_need_allow_ip() -> None:
    host_denied("8.8.8.8")
    result = host("8.8.8.8", allow_ip=True)
    assert result.is_ip
    assert result.name == "8.8.8.8"
    assert result.registered_domain is None


@pytest.mark.parametrize(
    "raw",
    [
        "127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.169.254",
        "0.0.0.0",  # noqa: S104 (a test input, not a bind address)
        "100.64.0.1", "[::1]", "[fc00::1]", "[fe80::1]", "[::ffff:127.0.0.1]", "[::]",
    ],
)
def test_private_and_local_addresses_are_denied(raw: str) -> None:
    host_denied(raw, allow_ip=True)


@pytest.mark.parametrize(
    "raw",
    ["2130706433", "0x7f.0.0.1", "0177.0.0.1", "127.1", "1.2.3", "999.1.1.1", "08.8.8.8",
     "0x7f000001", "[fe80::1%eth0]", "[::1", "[not-an-address]"],
)
def test_odd_number_hosts_are_denied(raw: str) -> None:
    host_denied(raw, allow_ip=True)


def test_global_ipv6_address_is_allowed_with_allow_ip() -> None:
    assert host("[2001:4860:4860::8888]", allow_ip=True).name == "[2001:4860:4860::8888]"


# ---------- URLs ----------

def test_url_is_cleaned() -> None:
    url = canonicalize_url("HTTPS://Example.COM/a/./b/../c/?x=1#frag")
    assert url.text == "https://example.com/a/c/?x=1"
    assert url.scheme == "https"
    assert url.host.name == "example.com"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://example.com", "https://example.com/"),
        ("https://example.com:443/x", "https://example.com/x"),
        ("http://example.com:80/x", "http://example.com/x"),
        ("https://example.com:80/x", "https://example.com:80/x"),
        ("https://example.com:8080/x", "https://example.com:8080/x"),
        ("https://example.com./x", "https://example.com/x"),
        ("https://example.com/a/..", "https://example.com/"),
        ("https://example.com/../../x", "https://example.com/x"),
        ("https://example.com/%2e%2e/x", "https://example.com/%2e%2e/x"),
        ("https://8.8.8.8/x", "https://8.8.8.8/x"),
        ("https://[2001:4860:4860::8888]:8443/x", "https://[2001:4860:4860::8888]:8443/x"),
    ],
)
def test_url_forms(raw: str, expected: str) -> None:
    assert canonicalize_url(raw).text == expected


@pytest.mark.parametrize(
    "raw",
    [
        "https://example.com@evil.com/",
        "https://user:pass@evil.com/",
        "https://@evil.com/",
        "https://example.com:443@evil.com/",
        "http://good.com%40evil.com@bad.example/",
    ],
)
def test_userinfo_tricks_are_denied(raw: str) -> None:
    url_denied(raw)


@pytest.mark.parametrize(
    ("raw", "expected_host"),
    [
        ("https://evil.example#@good.example", "evil.example"),
        ("https://good.example?@evil.example", "good.example"),
        ("https://good.example/@evil.example", "good.example"),
        ("https://good.example/https://evil.example", "good.example"),
    ],
)
def test_parser_picks_the_real_host_not_a_decoy(raw: str, expected_host: str) -> None:
    assert canonicalize_url(raw).host.name == expected_host


@pytest.mark.parametrize(
    "raw",
    [
        "ftp://example.com/", "javascript:alert(1)", "file:///etc/passwd", "//evil.example/x",
        "data:text/html,x", "https:evil.example", "https:/evil.example", "example.com", "",
        "https://", "https:///x",
    ],
)
def test_bad_schemes_and_missing_hosts_are_denied(raw: str) -> None:
    url_denied(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "https://example.com:/x", "https://example.com:0/x", "https://example.com:65536/x",
        "https://example.com:abc/x", "https://example.com:-1/x", "https://example.com:\uff18\uff10/x",
        "http://good.example:80:80/", "https://[::1/x", "https://[2001:4860:4860::8888]x/",
    ],
)
def test_bad_ports_and_brackets_are_denied(raw: str) -> None:
    url_denied(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "https://evil.example\\@good.example/", "https://exa mple.com/", "https://example.com/a b",
        "https://example.com/\n", "https://exa\tmple.com/", "https://example.com/\x00",
        " https://example.com/", "https://example.com/\u202e",
    ],
)
def test_whitespace_control_and_backslashes_are_denied(raw: str) -> None:
    url_denied(raw)


@pytest.mark.parametrize(
    "raw",
    [
        f"https://{CYRILLIC_A}pple.com/", "https://127.0.0.1/", "https://[::1]/",
        "https://169.254.169.254/latest/meta-data", "https://2130706433/", "https://localhost/",
        "https://intranet/", f"https://good.example{FULLWIDTH_AT}evil.example/",
    ],
)
def test_dangerous_destinations_are_denied(raw: str) -> None:
    url_denied(raw)


def test_fullwidth_host_is_mapped_to_the_real_host() -> None:
    raw = f"https://{FULLWIDTH_E}xample{IDEOGRAPHIC_DOT}com/x"
    assert canonicalize_url(raw).text == "https://example.com/x"


@pytest.mark.parametrize("raw", [None, 5, b"https://example.com", ["https://example.com"]])
def test_non_text_urls_are_denied(raw: object) -> None:
    url_denied(raw)


def test_very_long_url_is_denied() -> None:
    url_denied("https://example.com/" + "a" * 2000)


def test_allowed_schemes_can_be_narrowed() -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize_url("http://example.com/", allowed_schemes=("https",))


def test_url_policy_parts() -> None:
    parts = canonicalize_url("https://mail.company.co.in:8443/a/b?q=1").policy_parts()
    assert parts == {
        "scheme": "https",
        "domain": "mail.company.co.in",
        "registered_domain": "company.co.in",
        "port": 8443,
        "path": "/a/b",
    }


# ---------- emails ----------

def test_email_is_cleaned() -> None:
    email = canonicalize_email("Me.Name+tag@Company.COM")
    assert email.text == "me.name+tag@company.com"
    assert email.host.registered_domain == "company.com"


def test_email_trailing_dot_in_domain_is_removed() -> None:
    assert canonicalize_email("a@company.com.").text == "a@company.com"


def test_email_with_international_domain() -> None:
    assert canonicalize_email("a@b\u00fccher.example").text == "a@xn--bcher-kva.example"


@pytest.mark.parametrize(
    "raw",
    [
        "a@b@evil.com", "a@evil.com,b@good.com", "a@evil.com;b@good.com", "Name <a@b.com>",
        '"a@b"@evil.com', "user%evil.com@good.com", "a@[1.2.3.4]", "a@1.2.3.4", "a@localhost",
        f"a{FULLWIDTH_AT}b.com", f"a@evil.com{FULLWIDTH_AT}good.com", f"a@{CYRILLIC_A}pple.com",
        ".a@b.com", "a.@b.com", "a..b@b.com", "a@b", "@b.com", "a@", "a;b@b.com",
        "\u00fcn\u00ef@b.com", "a b@b.com", "a@b.com\n", "", None, 5, "x" * 300 + "@b.com",
        "a" * 65 + "@b.com", "a@evil.com\\@good.com",
    ],
)
def test_bad_emails_are_denied(raw: object) -> None:
    email_denied(raw)


def test_email_policy_parts() -> None:
    parts = canonicalize_email("Me@Mail.Company.co.in").policy_parts()
    assert parts == {
        "address": "me@mail.company.co.in",
        "local": "me",
        "domain": "mail.company.co.in",
        "registered_domain": "company.co.in",
    }


# ---------- allowlist ----------

@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("company.com", True),
        ("mail.company.com", True),
        ("a.b.company.com", True),
        ("evilcompany.com", False),
        ("company.com.evil.example", False),
        ("company.co", False),
        ("xn--cmpany-1ya.com", False),
    ],
)
def test_allowlist_matches_whole_names_only(name: str, expected: bool) -> None:
    assert is_allowed_domain(host(name), ["company.com"]) is expected


def test_allowlist_can_exclude_subdomains() -> None:
    assert is_allowed_domain(host("company.com"), ["company.com"], include_subdomains=False)
    sub = host("mail.company.com")
    assert not is_allowed_domain(sub, ["company.com"], include_subdomains=False)


def test_allowlist_with_several_entries_and_mixed_case() -> None:
    allowed = ["Company.com", "partner.co.in"]
    assert is_allowed_domain(host("x.partner.co.in"), allowed)
    assert not is_allowed_domain(host("other.co.in"), allowed)


def test_allowlist_never_matches_addresses() -> None:
    assert not is_allowed_domain(host("8.8.8.8", allow_ip=True), ["company.com"])


@pytest.mark.parametrize(
    "entry", ["com", "co.uk", "github.io", "1.2.3.4", "", "https://company.com", "a b.com"]
)
def test_bad_allowlist_entries_are_a_configuration_error(entry: str) -> None:
    with pytest.raises(ValueError, match="allowed domain"):
        is_allowed_domain(host("company.com"), [entry])


def test_allowlist_empty_means_nothing_is_allowed() -> None:
    assert not is_allowed_domain(host("company.com"), [])


# ---------- decision helper ----------

def test_block_for_does_not_repeat_the_raw_value() -> None:
    raw = "https://secret-token-123@evil.example/"
    try:
        canonicalize_url(raw)
    except CanonicalizationError as exc:
        decision = block_for("c1", "url", exc)
    assert decision.effect is Effect.BLOCK
    assert decision.reason_codes == [ReasonCode.CANONICALIZATION_FAILED]
    assert "secret-token-123" not in decision.main_reason


# ---------- properties (many random inputs) ----------

URL_PIECES = [
    "https://", "http://", "example.com", "evil.example", "a.b.co.uk", ":", "80", "443", "@",
    "/", "..", ".", " ", "\\", "?", "#", "x", "%2e", "[", "]", "::1", "1.2.3.4", "8.8.8.8",
    "\u0430", "\uff45", "\u3002", "b\u00fccher",
]
url_like = st.lists(st.sampled_from(URL_PIECES), max_size=12).map("".join)
anything = st.one_of(url_like, st.text(max_size=80))


@settings(max_examples=400, deadline=None)
@given(anything)
def test_property_canonicalizers_only_raise_canonicalization_error(raw: str) -> None:
    for function in (canonicalize_url, canonicalize_email, canonicalize_host):
        try:
            function(raw)  # type: ignore[operator]
        except CanonicalizationError:
            pass


@settings(max_examples=400, deadline=None)
@given(anything)
def test_property_urls_are_idempotent_and_hosts_are_clean(raw: str) -> None:
    try:
        url = canonicalize_url(raw)
    except CanonicalizationError:
        return
    assert canonicalize_url(url.text).text == url.text
    name = url.host.name
    assert name.isascii()
    assert name == name.lower()
    assert "@" not in name
    assert url.scheme in ("http", "https")


@settings(max_examples=300, deadline=None)
@given(anything)
def test_property_hosts_are_idempotent(raw: str) -> None:
    try:
        result = canonicalize_host(raw, allow_ip=True)
    except CanonicalizationError:
        return
    assert canonicalize_host(result.name, allow_ip=True) == result


@settings(max_examples=300, deadline=None)
@given(anything)
def test_property_emails_are_idempotent(raw: str) -> None:
    try:
        email = canonicalize_email(raw)
    except CanonicalizationError:
        return
    assert canonicalize_email(email.text) == email


@settings(max_examples=200, deadline=None)
@given(st.text(alphabet=string.ascii_letters + string.digits + ".-:", min_size=0, max_size=20))
def test_property_any_userinfo_is_denied(userinfo: str) -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize_url(f"https://{userinfo}@evil.example/")