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
from collections.abc import Callable
from typing import Any
from urllib.parse import unquote, urlsplit

BLOCKED_SUFFIXES = (".localhost", ".internal", ".local", ".localdomain", ".lan", ".home.arpa")
BLOCKED_NAMES = {"localhost", "metadata", "metadata.google.internal", "instance-data"}


def check_path(value: Any, roots: list[str]) -> str | None:
    if not isinstance(value, str) or not value:
        return "path must be a non-empty string"
    if "\x00" in value or any(ord(c) < 32 for c in value):
        return "control characters in path"
    forms = [value]
    for _ in range(3):  # catch single and nested percent-encoding
        nxt = unquote(forms[-1])
        if nxt == forms[-1]:
            break
        forms.append(nxt)
    for f in forms:
        norm = f.replace("\\", "/")
        if "\x00" in f or ".." in norm.split("/"):
            return "path traversal"
    for root in roots:
        real_root = os.path.realpath(root)
        cand = os.path.realpath(value if os.path.isabs(value) else os.path.join(real_root, value))
        try:
            if os.path.commonpath([real_root, cand]) == real_root:
                return None
        except ValueError:
            continue
    return "path is outside the allowed roots"


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


def check_url(value: Any, allow_hosts: list[str] | None = None,
              schemes: tuple[str, ...] = ("http", "https"),
              resolver: Callable[[str], list[str]] | None = None) -> str | None:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        return "url must be a clean non-empty string"
    if any(ord(c) < 32 for c in value) or "\\" in value:
        return "control characters or backslash in url"
    try:
        u = urlsplit(value)
        host = (u.hostname or "").lower().rstrip(".")
        _ = u.port
    except ValueError:
        return "unparseable url"
    if u.scheme.lower() not in schemes:
        return f"scheme {u.scheme!r} not allowed"
    if "@" in u.netloc:
        return "credentials/userinfo in url"
    if not host:
        return "missing host"
    ip = _parse_ip(host)
    if ip is not None:
        if not ip.is_global:
            return f"non-public address {ip}"
    else:
        if host in BLOCKED_NAMES or host.endswith(BLOCKED_SUFFIXES):
            return "internal hostname"
        if resolver is not None:
            for r in resolver(host):
                rip = _parse_ip(r)
                if rip is None or not rip.is_global:
                    return f"hostname resolves to non-public address {r}"
    if allow_hosts is not None and not any(
            host == a or host.endswith("." + a) for a in (x.lower() for x in allow_hosts)):
        return "host not in allow-list"
    return None


_SHELL = re.compile(r"[;|&`<>\n\r]|\$\(|\$\{")
_SQL = re.compile(r"('|\")\s*(or|and)\s+['\"\d]|--\s|/\*|;\s*(drop|delete|insert|update)\b|\bunion\s+select\b", re.I)


def check_injection(value: Any) -> str | None:
    """Heuristic: shell metacharacters and common SQL-injection shapes in a string argument."""
    if not isinstance(value, str):
        return None
    if _SHELL.search(value):
        return "shell metacharacters"
    if _SQL.search(value):
        return "sql injection pattern"
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
