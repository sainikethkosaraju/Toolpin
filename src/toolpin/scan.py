"""Static scan of tool definitions. THIS IS A HEURISTIC: it catches known-bad patterns and
obvious Unicode tricks. It will miss paraphrased or obfuscated instructions (see corpus misses).
The lockfile, not the scan, is the integrity control."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Any

from toolpin.canonical import tool_to_dict

PATTERNS = {
    "ignore-instructions": r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+(instructions|rules)",
    "important-tag": r"<\s*/?\s*(important|system|instructions?)\s*>",
    "conceal-from-user": r"(do\s+not|don't|never)\s+(tell|mention|reveal|inform|show|disclose)[^.]{0,30}\buser\b"
                         r"|without\s+(telling|informing|notifying|alerting)\s+the\s+user",
    "sensitive-file": r"(~/\.ssh|id_rsa|\.env\b|/etc/passwd|/etc/shadow|\.aws/credentials|\bapi[_ -]?keys?\b"
                      r"|\bcredentials\b|\bsecret[_ ]key\b|\bpassword\b)",
    "pre-call-directive": r"(before|prior\s+to|first)\s+(you\s+)?(use|using|call|calling|run|running|invok\w+)\s+"
                          r"(this|the)\s+tool",
    "system-prompt": r"\bsystem\s+prompt\b",
    "forced-call": r"you\s+(must|should|need\s+to)\s+(also\s+)?(call|use|invoke|send|read|include)",
    "exfil-verb": r"\b(exfiltrate|upload|forward|transmit)\b[^.]{0,40}\b(to|http)",
    "long-base64": r"[A-Za-z0-9+/]{48,}={0,2}",
}
_COMPILED = {k: re.compile(v, re.I) for k, v in PATTERNS.items()}
ZERO_WIDTH = {"​", "‌", "‍", "⁠", "﻿", "­"}
BIDI = {chr(c) for c in (*range(0x202A, 0x202F), *range(0x2066, 0x206A))}


@dataclass(frozen=True)
class Finding:
    rule: str
    where: str
    detail: str


def _strings(o: Any, path: str = "") -> list[tuple[str, str]]:
    if isinstance(o, str):
        return [(path, o)]
    out: list[tuple[str, str]] = []
    if isinstance(o, dict):
        for k, v in o.items():
            out += _strings(v, f"{path}.{k}" if path else str(k))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            out += _strings(v, f"{path}[{i}]")
    return out


def _mixed_script(word: str) -> bool:
    latin = other = False
    for ch in word:
        if not ch.isalpha():
            continue
        n = unicodedata.name(ch, "")
        if n.startswith("LATIN"):
            latin = True
        elif n.startswith(("CYRILLIC", "GREEK")):
            other = True
    return latin and other


def scan_text(text: str, where: str = "") -> list[Finding]:
    f: list[Finding] = []
    if any(c in text for c in ZERO_WIDTH):
        f.append(Finding("zero-width-char", where, "contains zero-width characters"))
    if any(c in text for c in BIDI):
        f.append(Finding("bidi-control", where, "contains bidirectional control characters"))
    if any(0xE0000 <= ord(c) <= 0xE007F for c in text):
        f.append(Finding("unicode-tag-chars", where, "contains invisible tag characters"))
    for w in re.findall(r"\w+", text):
        if _mixed_script(w):
            f.append(Finding("mixed-script-word", where, f"look-alike letters in {w!r}"))
            break
    for rule, rx in _COMPILED.items():
        if rx.search(text):
            f.append(Finding(rule, where, "pattern match"))
    return f


def scan_tool(tool: Any) -> list[Finding]:
    d = tool_to_dict(tool)
    out: list[Finding] = []
    for where, s in _strings({k: v for k, v in d.items() if k != "name"}):
        out += scan_text(s, where)
    out += scan_text(d["name"], "name")
    return out


def _skeleton(name: str) -> str:
    n = unicodedata.normalize("NFKC", name).casefold().strip()
    n = "".join(ch for ch in n if ch not in ZERO_WIDTH)
    return re.sub(r"[\s_\-.]+", "", n)


def check_shadowing(tool_name: str, known: list[str]) -> list[Finding]:
    """A different server claiming a name that is, or visually collapses to, a known tool name."""
    sk = _skeleton(tool_name)
    out = []
    for k in known:
        if tool_name == k:
            out.append(Finding("shadow-exact", "name", f"duplicates {k!r}"))
        elif sk == _skeleton(k):
            out.append(Finding("shadow-lookalike", "name", f"collapses to {k!r}"))
        elif _mixed_script(tool_name) and sk != tool_name:
            out.append(Finding("shadow-mixed-script", "name", f"mixed scripts near {k!r}"))
    return out
