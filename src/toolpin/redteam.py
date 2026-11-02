"""Mutation-based red-team fuzzer for the heuristic controls (scan, url, path, args, shadow).

Each operator rewrites a known attack so that it means the same thing to its target while changing the
bytes a detector sees. The evasion rate of an operator = fraction of SEED attacks that the control blocked
in plain form but misses after mutation. Everything is deterministic given a seed.

Operator families and their assumed semantic equivalence (documented, not proved):
  * text    : case, spacing, zero-width, homoglyph, fullwidth, leetspeak, comment wrapping, padding,
              base64/rot13 (needs a decode-capable target), translation (phrase table, small)
  * url     : IP re-encodings (decimal/hex/octal/mixed/ipv4-mapped), trailing dot, fullwidth and
              ideographic dots, percent-encoded host, userinfo / fragment tricks. Whether a given HTTP client
              resolves a form to the same address is client-dependent; any form some common client resolves counts
  * path    : percent / double / overlong encodings, backslashes, repeated dots, fullwidth dots, null bytes
  * args    : comment- and IFS-based whitespace substitution, case mixing, URL-encoding, fullwidth
"""
from __future__ import annotations

import base64
import codecs
import ipaddress
import random
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass

CYR = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "x": "х", "y": "у", "i": "і", "s": "ѕ"}
LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}
PHRASES = {  # tiny translation table for the seed phrases the corpus uses
    "ignore all previous instructions": ["ignora todas las instrucciones anteriores", "ignorez toutes les instructions précédentes",
                                         "ignoriere alle vorherigen anweisungen", "ignora tutte le istruzioni precedenti",
                                         "игнорируй все предыдущие инструкции", "忽略之前的所有指令"],
    "do not tell the user": ["no se lo digas al usuario", "ne le dites pas à l'utilisateur",
                             "sage es dem benutzer nicht", "не говори пользователю", "不要告诉用户"],
}


@dataclass(frozen=True)
class Mutant:
    operator: str
    family: str
    value: str


def _spaced(s: str, rng) -> str: return " ".join(s)
def _zw(s: str, rng) -> str: return "​".join(s[i:i + 3] for i in range(0, len(s), 3))
def _homoglyph(s: str, rng) -> str: return "".join(CYR.get(c, c) if rng.random() < 0.7 else c for c in s)
def _fullwidth(s: str, rng) -> str: return "".join(chr(ord(c) + 0xFEE0) if 0x21 <= ord(c) <= 0x7E else c for c in s)
def _leet(s: str, rng) -> str: return "".join(LEET.get(c.lower(), c) for c in s)
def _case(s: str, rng) -> str: return "".join(c.upper() if rng.random() < 0.5 else c.lower() for c in s)
def _htmlc(s: str, rng) -> str: return f"Helper tool. <!-- {s} -->"
def _fence(s: str, rng) -> str: return f"Usage notes:\n```\n{s}\n```"
def _nbsp(s: str, rng) -> str: return s.replace(" ", " ")
def _tabs(s: str, rng) -> str: return s.replace(" ", "\t\n")
def _pad(s: str, rng) -> str: return ("This tool reads files, handles UTF-8 and symlinks and logs each request. " * 3) + s
def _b64(s: str, rng) -> str: return "Note: " + base64.b64encode(s.encode()).decode()
def _rot13(s: str, rng) -> str: return codecs.encode(s, "rot13") + " (rot13)"
def _soft(s: str, rng) -> str: return "­".join(s)


def _translate(s: str, rng) -> str:
    low = s.lower()
    for en, outs in PHRASES.items():
        if en in low:
            return low.replace(en, rng.choice(outs))
    return s


TEXT_OPS: dict[str, Callable] = {"spaced": _spaced, "zero_width": _zw, "homoglyph": _homoglyph, "fullwidth": _fullwidth,
                                 "leetspeak": _leet, "mixed_case": _case, "html_comment": _htmlc, "code_fence": _fence,
                                 "nbsp": _nbsp, "tabs": _tabs, "padding": _pad, "base64": _b64, "rot13": _rot13,
                                 "soft_hyphen": _soft, "translate": _translate}


def _ip_forms(ip: str) -> list[tuple[str, str]]:
    a = ipaddress.IPv4Address(ip)
    n = int(a)
    o = [int(x) for x in ip.split(".")]
    return [("decimal", str(n)), ("hex", hex(n)), ("octal", "0" + oct(n)[2:]),
            ("mixed_radix", f"0x{o[0]:x}.{o[1]}.{o[2]}.{o[3]}"), ("octal_octets", ".".join("0" + oct(x)[2:] for x in o)),
            ("leading_zeros", ".".join(f"{x:03d}" for x in o)), ("ipv4_mapped", f"[::ffff:{ip}]"),
            ("ipv4_mapped_hex", f"[::ffff:{o[0]:02x}{o[1]:02x}:{o[2]:02x}{o[3]:02x}]"), ("trailing_dot", ip + "."),
            ("fullwidth", "".join(chr(ord(c) + 0xFEE0) if c.isdigit() else "．" if c == "." else c for c in ip)),
            ("ideographic_dots", ip.replace(".", "。")), ("pct_encoded", "".join(f"%{ord(c):02x}" if c.isdigit() else c for c in ip))]


def url_mutants(url: str) -> list[Mutant]:
    p = urllib.parse.urlsplit(url)
    host = p.hostname or ""
    out: list[Mutant] = []
    def rebuild(h: str) -> str: return urllib.parse.urlunsplit((p.scheme, h + (f":{p.port}" if p.port else ""), p.path, p.query, p.fragment))
    try:
        ipaddress.IPv4Address(host)
        for name, h in _ip_forms(host):
            out.append(Mutant(f"ip_{name}", "url", rebuild(h)))
    except ValueError:
        pass
    out.append(Mutant("trailing_dot_host", "url", rebuild(host + ".")))
    out.append(Mutant("userinfo_prefix", "url", urllib.parse.urlunsplit((p.scheme, f"public.example.com@{host}", p.path, p.query, p.fragment))))
    out.append(Mutant("upper_scheme", "url", url.replace(p.scheme, p.scheme.upper(), 1)))
    out.append(Mutant("tab_in_url", "url", url.replace("//", "//\t", 1)))
    out.append(Mutant("backslash_authority", "url", url.replace("://", ":\\\\", 1)))
    return out


def path_mutants(path: str) -> list[Mutant]:
    out = [Mutant("percent_encoded", "path", path.replace("/", "%2f").replace(".", "%2e")),
           Mutant("double_encoded", "path", path.replace("/", "%252f").replace(".", "%252e")),
           Mutant("overlong_slash", "path", path.replace("/", "%c0%af")),
           Mutant("backslash", "path", path.replace("/", "\\")),
           Mutant("percent_backslash", "path", path.replace("/", "%5c")),
           Mutant("repeated_dots", "path", path.replace("../", "....//")),
           Mutant("fullwidth_dots", "path", path.replace(".", "．")),
           Mutant("mixed_slashes", "path", path.replace("/", "/\\")),
           Mutant("null_mid", "path", path.replace("/", "%00/", 1)),
           Mutant("dot_segments", "path", path.replace("../", "./../")),
           Mutant("file_scheme", "path", "file://" + path.lstrip("/")),
           Mutant("trailing_space", "path", path + " ")]
    return out


def arg_mutants(v: str) -> list[Mutant]:
    return [Mutant("comment_space", "args", v.replace(" ", "/**/")), Mutant("ifs_space", "args", v.replace(" ", "${IFS}")),
            Mutant("tab_space", "args", v.replace(" ", "\t")), Mutant("url_encoded", "args", urllib.parse.quote(v, safe="")),
            Mutant("double_url_encoded", "args", urllib.parse.quote(urllib.parse.quote(v, safe=""), safe="")),
            Mutant("fullwidth", "args", _fullwidth(v, None)), Mutant("case_mix", "args", _case(v, random.Random(1))),
            Mutant("split_keyword", "args", v.replace("UNION", "UN/**/ION").replace("SELECT", "SEL/**/ECT").replace("DROP", "DR/**/OP")),
            Mutant("newline_instead_of_space", "args", v.replace(" ", "\n"))]


def text_mutants(s: str, seed: int = 0) -> list[Mutant]:
    rng = random.Random(seed)
    return [Mutant(name, "text", fn(s, rng)) for name, fn in TEXT_OPS.items()]


def name_mutants(name: str) -> list[Mutant]:
    return [Mutant("fullwidth", "name", _fullwidth(name, None)), Mutant("upper", "name", name.upper()),
            Mutant("camel", "name", "".join(w.capitalize() if i else w for i, w in enumerate(name.split("_")))),
            Mutant("homoglyph", "name", _homoglyph(name, random.Random(2))), Mutant("soft_hyphen", "name", name.replace("_", "­")),
            Mutant("space_sep", "name", name.replace("_", " ")), Mutant("digit_lookalike", "name", name.replace("l", "1").replace("o", "0")),
            Mutant("dot_sep", "name", name.replace("_", "."))]
