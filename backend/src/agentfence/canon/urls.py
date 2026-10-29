"""URL, host and email canonicalizers (Day 10).

Each function returns one canonical form or raises CanonicalizationError.
Policy compares the canonical values, never the raw text.

What this does:
- Real parsing (urllib), after rejecting whitespace, control characters and backslashes.
- Hosts become lowercase ASCII (punycode for international names).
- Mixed script labels (for example Latin plus Cyrillic) are denied.
- Userinfo (name@host), odd numeric hosts and private or local addresses are denied.
- The registered domain is computed with a small built in suffix list.

What this does NOT do: it cannot prove a destination is safe. Trust comes from
explicit allowlists (is_allowed_domain) and policy. Percent encoding is decoded
by Day 11 before these functions run.
"""
import ipaddress
import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from urllib.parse import urlsplit

from agentfence.canon.errors import CanonicalizationError

MAX_URL_CHARS = 2000
MAX_HOST_CHARS = 253
MAX_EMAIL_CHARS = 254
MAX_LOCAL_CHARS = 64
DEFAULT_PORTS = {"http": 80, "https": 443}
LABEL_PATTERN = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
LOCAL_PATTERN = re.compile(r"^[A-Za-z0-9._+\-]{1,64}$")
NUMERIC_LABEL = re.compile(r"^(0x[0-9a-f]*|[0-9]+)$")

# Names that point inside a network. Never a valid outside destination.
LOCAL_SUFFIXES = (
    "localhost",
    "local",
    "internal",
    "localdomain",
    "lan",
    "home.arpa",
    "intranet",
    "corp",
    "arpa",
)

# A small list of multi label public suffixes. It is NOT the full public suffix
# list. If a suffix is missing here, the registered domain comes out too short.
# That fails safe: it can only cause a mismatch, never a false match.
MULTI_LABEL_SUFFIXES = frozenset(
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "org.in", "net.in", "ac.in", "gov.in",
        "res.in", "nic.in", "edu.in", "com.au", "net.au", "org.au", "edu.au", "gov.au",
        "co.nz", "co.jp", "ne.jp", "or.jp", "ac.jp", "com.br", "com.cn", "com.sg", "com.mx",
        "co.za", "co.kr", "com.hk", "com.tw", "com.tr", "com.ar", "co.id",
        # Hosting services where every customer shares one parent name.
        "github.io", "gitlab.io", "herokuapp.com", "vercel.app", "netlify.app", "pages.dev",
        "workers.dev", "web.app", "firebaseapp.com", "blogspot.com", "appspot.com",
        "azurewebsites.net", "cloudfront.net", "s3.amazonaws.com", "ngrok.io",
        "ngrok-free.app", "trycloudflare.com",
    }
)


@dataclass(frozen=True)
class CanonicalHost:
    name: str  # lowercase ASCII, punycode for international names, or an IP address
    registered_domain: str | None  # None for IP addresses and for bare public suffixes
    is_ip: bool = False
    is_idn: bool = False


@dataclass(frozen=True)
class CanonicalUrl:
    scheme: str
    host: CanonicalHost
    port: int | None  # None when it is the default port for the scheme
    path: str
    query: str

    @property
    def text(self) -> str:
        port = f":{self.port}" if self.port is not None else ""
        query = f"?{self.query}" if self.query else ""
        return f"{self.scheme}://{self.host.name}{port}{self.path}{query}"

    def policy_parts(self) -> dict[str, str | int | None]:
        """Values for policy fields such as args.url.registered_domain."""
        return {
            "scheme": self.scheme,
            "domain": self.host.name,
            "registered_domain": self.host.registered_domain,
            "port": self.port,
            "path": self.path,
        }


@dataclass(frozen=True)
class CanonicalEmail:
    local: str
    host: CanonicalHost

    @property
    def text(self) -> str:
        return f"{self.local}@{self.host.name}"

    def policy_parts(self) -> dict[str, str | int | None]:
        return {
            "address": self.text,
            "local": self.local,
            "domain": self.host.name,
            "registered_domain": self.host.registered_domain,
        }


# ---------- helpers ----------

def _plain_text(raw: object, max_chars: int, what: str) -> str:
    if not isinstance(raw, str):
        raise CanonicalizationError(f"{what} must be text")
    if not raw.strip():
        raise CanonicalizationError(f"{what} is empty")
    if len(raw) > max_chars:
        raise CanonicalizationError(f"{what} is too long")
    for char in raw:
        if char == "\\":
            raise CanonicalizationError(f"backslashes are not allowed in {what}")
        if char.isspace() or unicodedata.category(char)[0] == "C":
            raise CanonicalizationError(
                f"spaces and control characters are not allowed in {what}"
            )
    return raw


def _script_of(char: str) -> str | None:
    if char.isdigit() or char == "-":
        return None
    try:
        return unicodedata.name(char).split(" ", 1)[0]
    except ValueError:
        return "UNKNOWN"


def _check_one_script(label: str) -> None:
    scripts = {s for s in (_script_of(c) for c in label) if s is not None}
    if len(scripts) > 1:
        raise CanonicalizationError("a name part mixes different alphabets")


def registered_domain(name: str) -> str | None:
    """The registered domain of an ASCII host name, or None if there is none."""
    labels = name.split(".")
    suffix_len = 1
    for size in (3, 2):
        if len(labels) >= size and ".".join(labels[-size:]) in MULTI_LABEL_SUFFIXES:
            suffix_len = size
            break
    if len(labels) <= suffix_len:
        return None
    return ".".join(labels[-(suffix_len + 1):])


def _ip_host(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> CanonicalHost:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if not ip.is_global:
        raise CanonicalizationError("private, local or reserved addresses are not allowed")
    name = f"[{ip.compressed}]" if ip.version == 6 else str(ip)
    return CanonicalHost(name=name, registered_domain=None, is_ip=True)


# ---------- hosts ----------

def canonicalize_host(raw: object, *, allow_ip: bool = False) -> CanonicalHost:
    text = _plain_text(raw, MAX_HOST_CHARS, "the host")

    if text.startswith("["):
        if not allow_ip or not text.endswith("]") or "%" in text:
            raise CanonicalizationError("address hosts are not allowed here")
        try:
            return _ip_host(ipaddress.IPv6Address(text[1:-1]))
        except ValueError as exc:
            raise CanonicalizationError("not a valid address") from exc

    if text.endswith("."):
        text = text[:-1]
    if not text or text.endswith("."):
        raise CanonicalizationError("host has an empty name part")

    try:
        name = text.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise CanonicalizationError("host is not a valid name") from exc
    if len(name) > MAX_HOST_CHARS:
        raise CanonicalizationError("host is too long")

    labels = name.split(".")
    if NUMERIC_LABEL.match(labels[-1]):
        try:
            ip = ipaddress.IPv4Address(name)
        except ValueError as exc:
            raise CanonicalizationError("ambiguous number host") from exc
        if not allow_ip:
            raise CanonicalizationError("address hosts are not allowed here")
        return _ip_host(ip)

    if len(labels) < 2:
        raise CanonicalizationError("host needs at least two name parts")
    is_idn = False
    for label in labels:
        if not LABEL_PATTERN.match(label):
            raise CanonicalizationError("host has an invalid name part")
        if label.startswith("xn--"):
            is_idn = True
            try:
                shown = label.encode("ascii").decode("idna")
            except UnicodeError as exc:
                raise CanonicalizationError("host has an invalid international name") from exc
            _check_one_script(shown)
    for suffix in LOCAL_SUFFIXES:
        if name == suffix or name.endswith("." + suffix):
            raise CanonicalizationError("local or internal names are not allowed")
    return CanonicalHost(name=name, registered_domain=registered_domain(name), is_idn=is_idn)


def is_allowed_domain(
    host: CanonicalHost, allowed_domains: Sequence[str], *, include_subdomains: bool = True
) -> bool:
    """True if the host is one of the allowed domains (or a subdomain of one).

    Entries are checked as configuration. A bad entry, or an entry that is a
    public suffix such as 'com' or 'co.uk', raises ValueError.
    """
    allowed_names = []
    for entry in allowed_domains:
        try:
            parsed = canonicalize_host(entry)
        except CanonicalizationError as exc:
            raise ValueError(f"bad allowed domain: {entry!r}") from exc
        if parsed.registered_domain is None:
            raise ValueError(f"allowed domain is a public suffix: {entry!r}")
        allowed_names.append(parsed.name)
    if host.is_ip:
        return False
    return any(
        host.name == allowed or (include_subdomains and host.name.endswith("." + allowed))
        for allowed in allowed_names
    )


# ---------- URLs ----------

def _remove_dot_segments(path: str) -> str:
    out = [""]
    segments = path.split("/")[1:]
    for segment in segments:
        if segment == ".":
            continue
        if segment == "..":
            if len(out) > 1:
                out.pop()
            continue
        out.append(segment)
    if segments and segments[-1] in (".", ".."):
        out.append("")
    return "/".join(out) or "/"


def _split_netloc(netloc: str) -> tuple[str, str | None]:
    if netloc.startswith("["):
        end = netloc.find("]")
        if end == -1:
            raise CanonicalizationError("bad address brackets")
        host, rest = netloc[: end + 1], netloc[end + 1 :]
        if rest and not rest.startswith(":"):
            raise CanonicalizationError("unexpected text after the address")
        return host, (rest[1:] if rest else None)
    if netloc.count(":") > 1:
        raise CanonicalizationError("too many colons in the host part")
    host, _, port = netloc.partition(":")
    return host, (port if ":" in netloc else None)


def canonicalize_url(
    raw: object, *, allowed_schemes: Sequence[str] = ("http", "https")
) -> CanonicalUrl:
    text = _plain_text(raw, MAX_URL_CHARS, "the URL")
    try:
        parts = urlsplit(text)
    except ValueError as exc:
        raise CanonicalizationError("URL could not be parsed") from exc

    scheme = parts.scheme.lower()
    if scheme not in allowed_schemes:
        raise CanonicalizationError("URL scheme is not allowed")
    if not parts.netloc:
        raise CanonicalizationError("URL has no host")
    if "@" in parts.netloc:
        raise CanonicalizationError("user names and passwords in URLs are not allowed")

    host_text, port_text = _split_netloc(parts.netloc)
    host = canonicalize_host(host_text, allow_ip=True)

    port: int | None = None
    if port_text is not None:
        if not (port_text.isascii() and port_text.isdigit()):
            raise CanonicalizationError("port is not a number")
        number = int(port_text)
        if not 1 <= number <= 65535:
            raise CanonicalizationError("port is out of range")
        if number != DEFAULT_PORTS.get(scheme):
            port = number

    return CanonicalUrl(
        scheme=scheme,
        host=host,
        port=port,
        path=_remove_dot_segments(parts.path),
        query=parts.query,
    )


# ---------- emails ----------

def canonicalize_email(raw: object) -> CanonicalEmail:
    text = _plain_text(raw, MAX_EMAIL_CHARS, "the email address")
    if text.count("@") != 1:
        raise CanonicalizationError("an email address needs exactly one at sign")
    local, domain = text.split("@")
    bad_dots = local.startswith(".") or local.endswith(".") or ".." in local
    if not LOCAL_PATTERN.match(local) or bad_dots:
        raise CanonicalizationError("email name part has unsupported characters")
    host = canonicalize_host(domain, allow_ip=False)
    return CanonicalEmail(local=local.lower(), host=host)