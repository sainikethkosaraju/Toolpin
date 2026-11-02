"""Argument constraints: path and URL allow-lists, SSRF checks (stdlib `ipaddress`), injection
heuristics, numeric ceilings. Every function returns None when OK or a reason string.

Limits (documented in docs/limits.md): the URL check is static unless you pass `resolver`; a
hostname that resolves to a private address at fetch time (DNS rebinding) is only caught if you
resolve and pin the address yourself. The injection check is a heuristic."""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import unicodedata
from collections.abc import Callable
from typing import Any
from urllib.parse import unquote, urlsplit

from toolpin.normalize import strip_invisible

BLOCKED_SUFFIXES = (".localhost", ".internal", ".local", ".localdomain", ".lan", ".home.arpa")
BLOCKED_NAMES = {"localhost", "metadata", "metadata.google.internal", "instance-data"}


OVERLONG = re.compile(r"%c0%a[ef]|%c1%(9c|1c|af)|%e0%80%a[ef]|%f0%80%80%a[ef]", re.I)
DOTS_ONLY = re.compile(r"^\.{2,}$")


def check_path(value: Any, roots: list[str]) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return "path must be a non-empty string"
    if value.lstrip().startswith("~") or "$" in value or "`" in value:
        return "shell expansion (~, $VAR, backticks) in path"
    if "\\" in value or "%5c" in value.lower() or "%255c" in value.lower():
        return "backslash in path (POSIX roots only; rejected to avoid platform-dependent meaning)"
    if "\x00" in value or any(ord(c) < 32 for c in value):
        return "control characters in path"
    if OVERLONG.search(value) or "%00" in value.lower():
        return "overlong UTF-8 or encoded NUL in path"
    forms = [value]
    for _ in range(5):  # peel nested percent-encoding
        nxt = unquote(forms[-1])
        if nxt == forms[-1]:
            break
        forms.append(nxt)
    for f in forms:
        g = unicodedata.normalize("NFKC", f)
        g = strip_invisible(g)
        if "\x00" in g or "://" in g or g.startswith(("\\\\", "//")) and "\\" in g[:2]:
            return "scheme, UNC or NUL in path"
        for seg in re.split(r"[/\\]+", g):
            seg = seg.split(";")[0]                                # servlet-style path parameters: '..;/'
            core = seg.rstrip(" .") if seg.strip(" .") else seg   # Windows ignores trailing dots/spaces
            if seg == ".." or core == ".." or DOTS_ONLY.match(seg.strip()):
                return "path traversal"
    # EVERY decoded reading must stay inside a root: a backend that decodes sees a different path
    for f in forms:
        real_value = unicodedata.normalize("NFKC", strip_invisible(f))
        inside = False
        for root in roots:
            real_root = os.path.realpath(root)
            cand = os.path.realpath(real_value if os.path.isabs(real_value) else os.path.join(real_root, real_value))
            try:
                inside = inside or os.path.commonpath([real_root, cand]) == real_root
            except ValueError:
                continue
        if not inside:
            return "path is outside the allowed roots"
    return None


def _parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    h = host.strip("[]")
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        ip = None
        if ":" not in h:
            try:  # inet_aton accepts decimal, hex, octal and short forms: 2130706433, 0x7f000001, 127.1
                ip = ipaddress.IPv4Address(socket.inet_aton(h))
            except OSError:
                return None
        else:
            return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


CANONICAL_V4 = re.compile(r"^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$")


_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_COMPAT = ipaddress.ip_network("::/96")
_SIX_TO_FOUR = ipaddress.ip_network("2002::/16")


def _embedded_v4(ip) -> ipaddress.IPv4Address | None:
    """IPv4 hidden inside an IPv6 literal: IPv4-compatible (::a.b.c.d), NAT64, 6to4."""
    if isinstance(ip, ipaddress.IPv6Address):
        if ip in _COMPAT and int(ip) > 1:
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if ip in _NAT64:
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if ip in _SIX_TO_FOUR:
            return ipaddress.IPv4Address((int(ip) >> 80) & 0xFFFFFFFF)
    return None


def check_url(value: Any, allow_hosts: list[str] | None = None,
              schemes: tuple[str, ...] = ("http", "https"),
              resolver: Callable[[str], list[str]] | None = None) -> str | None:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        return "url must be a clean non-empty string"
    if any(ord(c) < 32 for c in value) or "\\" in value:
        return "control characters or backslash in url"
    value = unicodedata.normalize("NFKC", strip_invisible(value))   # fullwidth digits/dots
    value = value.replace("\u3002", ".").replace("\uff61", ".").replace("\uff0e", ".")   # label separators browsers/IDNA accept
    try:
        u = urlsplit(value)
        raw_host = u.hostname or ""
        _ = u.port
    except ValueError:
        return "unparseable url"
    if u.scheme.lower() not in schemes:
        return f"scheme {u.scheme!r} not allowed"
    if "@" in u.netloc:
        return "credentials/userinfo in url"
    host = unquote(raw_host).lower().rstrip(".")
    if "%" in host or not host:
        return "missing or malformed host"
    if re.fullmatch(r"[0-9.]+", host) and not CANONICAL_V4.match(host):
        return "ambiguous IPv4 notation (only canonical dotted-decimal is accepted)"
    ip = _parse_ip(host)
    if ip is not None:
        if not CANONICAL_V4.match(host) and "." in host and ":" not in host:
            return "non-canonical IPv4 notation"
        if not ip.is_global:
            return f"non-public address {ip}"
        inner = _embedded_v4(ip)
        if inner is not None and not inner.is_global:
            return f"non-public IPv4 {inner} embedded in IPv6 literal"
        if isinstance(ip, ipaddress.IPv6Address) and ip in _COMPAT:
            return "deprecated IPv4-compatible IPv6 literal"
    else:
        try:
            ascii_host = host.encode("idna").decode()
        except UnicodeError:
            return "invalid internationalised host name"
        if not re.fullmatch(r"(?:[a-z0-9_](?:[a-z0-9_\-]{0,61}[a-z0-9_])?)(?:\.[a-z0-9_](?:[a-z0-9_\-]{0,61}[a-z0-9_])?)*", ascii_host) \
                or len(ascii_host) > 253:
            return "malformed host name"
        if ascii_host in BLOCKED_NAMES or ascii_host.endswith(BLOCKED_SUFFIXES):
            return "internal hostname"
        if re.search(r"(^|\.)(\d{1,3}\.){3}\d{1,3}\.(nip|sslip|xip)\.io$|(^|\.)localtest\.me$|(^|\.)lvh\.me$", ascii_host):
            return "wildcard-DNS name that resolves to an embedded address"
        if resolver is not None:
            for r in resolver(ascii_host):
                rip = _parse_ip(r)
                if rip is None or not rip.is_global:
                    return f"hostname resolves to non-public address {r}"
        host = ascii_host
    if allow_hosts is not None and not any(
            host == a or host.endswith("." + a) for a in (x.lower() for x in allow_hosts)):
        return "host not in allow-list"
    return None


_SHELL = re.compile(r"[;|&`<>\n\r]|\$\(|\$\{")
_SQL = re.compile(r"('|\")\s*(or|and)\s+['\"\d]|'\s*--|--\s|/\*|;\s*(drop|delete|insert|update|truncate)\b|\bunion\s+(all\s+)?select\b", re.I)
_ANSIC = re.compile(r"\$'[^']*\\x[0-9a-f]{2}", re.I)
_SQLHASH = re.compile(r"'\s*#|\bor\b\s+\d+\s*=\s*\d+|0x[0-9a-f]{8,}|\bchar\s*\(\s*\d+(\s*,\s*\d+)+\s*\)", re.I)
_BRACE = re.compile(r"\{[^{}\s]+,[^{}\s]*\}")
_JNDI = re.compile(r"\$\{\s*(jndi|env|sys|lower|upper|java)\s*:", re.I)
_FLAGS = re.compile(r"(^|\s)--(upload-pack|exec|receive-pack|output|config|eval|command|shell)\b", re.I)


def _injection_readings(value: str) -> list[str]:
    """Unicode-fold FIRST (so fullwidth %3B becomes %3B), then peel percent-encoding, keeping newlines
    (CRLF injection) and also offering comment-/IFS-as-whitespace and collapsed-whitespace readings."""
    from toolpin.normalize import fold_keep_ws
    out, cur = [], fold_keep_ws(value)
    for _ in range(4):
        out.append(cur)
        nxt = fold_keep_ws(unquote(cur))
        if nxt == cur:
            break
        cur = nxt
    readings = []
    for r in out:
        r2 = re.sub(r"/\*.*?\*/", " ", r)             # SQL comments used as whitespace
        r2 = re.sub(r"\$\{?IFS\}?", " ", r2)           # shell field separator
        r2 = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), r2)   # \u003b
        r2 = re.sub(r"&#(\d+);", lambda m: chr(int(m.group(1))) if int(m.group(1)) < 0x110000 else "", r2)   # &#59;
        readings += [r, r2, re.sub(r"\s+", " ", r2), re.sub(r"\\\n", " ", r2)]
    return readings


def check_injection(value: Any) -> str | None:
    """Heuristic: shell metacharacters, SQL-injection shapes, JNDI lookups and dangerous option flags,
    checked on the raw value and on its decoded / comment-stripped / Unicode-folded readings."""
    if not isinstance(value, str):
        return None
    raw_hit = _SHELL.search(value)
    for r in [value, *_injection_readings(value)]:
        if _SHELL.search(r):
            return "shell metacharacters" if r == value or raw_hit else "shell metacharacters (after decoding)"
        if _SQL.search(r) or _SQLHASH.search(r):
            return "sql injection pattern"
        if _ANSIC.search(r) or _BRACE.search(r) and re.search(r"[/\\]", r):
            return "shell quoting / brace-expansion trick"
        if _JNDI.search(r):
            return "lookup-expression injection"
        if _FLAGS.search(r):
            return "dangerous command-line option"
    return None


def check_number(value: Any, ceiling: float | None = None, floor: float | None = None) -> str | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return "not a number"
    if value != value or value in (float("inf"), float("-inf")):
        return "non-finite number"
    if ceiling is not None and value > ceiling:
        return f"exceeds ceiling {ceiling}"
    if floor is not None and value < floor:
        return f"below floor {floor}"
    return None


def check_arguments(arguments: dict[str, Any], spec: dict[str, Any]) -> str | None:
    """spec: {path_args: {arg: [roots]}, url_args: {arg: {allow_hosts: [...]}}, safe_args: [arg],
    max: {arg: n}, min: {arg: n}}"""
    for a, roots in (spec.get("path_args") or {}).items():
        if a in arguments and (r := check_path(arguments[a], roots)):
            return f"{a}: {r}"
    for a, opts in (spec.get("url_args") or {}).items():
        if a in arguments and (r := check_url(arguments[a], (opts or {}).get("allow_hosts"))):
            return f"{a}: {r}"
    for a in spec.get("safe_args") or []:
        if a in arguments and (r := check_injection(arguments[a])):
            return f"{a}: {r}"
    for a, n in (spec.get("max") or {}).items():
        if a in arguments and (r := check_number(arguments[a], ceiling=n)):
            return f"{a}: {r}"
    for a, n in (spec.get("min") or {}).items():
        if a in arguments and (r := check_number(arguments[a], floor=n)):
            return f"{a}: {r}"
    return None
