"""Canonicalisation shared by the heuristic controls. Detectors see the text an attacker WANTS the model
to read, not the bytes the attacker chose to hide it in.

Pipeline: NFKC (fullwidth, ligatures, compatibility forms) -> drop invisible format/control characters
(zero-width, soft hyphen, bidi) -> fold look-alike letters (Cyrillic/Greek -> Latin) -> collapse whitespace.
`variants()` additionally yields decoded and de-obfuscated forms (letter-spaced, leetspeak, percent,
base64, hex, rot13) so a pattern is matched in every reading a capable model could plausibly recover."""
from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import unicodedata
import urllib.parse

CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ѕ": "s", "ј": "j", "ԁ": "d",
    "һ": "h", "ո": "n", "ս": "u", "ν": "v", "α": "a", "ε": "e", "ι": "i", "κ": "k", "ρ": "p", "τ": "t",
    "υ": "u", "χ": "x", "ᴀ": "a", "ɡ": "g", "ɩ": "i", "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
    "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X",
    "І": "I", "Ѕ": "S", "Ј": "J", "Ԁ": "D", "Ԛ": "Q", "Ԝ": "W", "Ү": "Y", "Ӏ": "I", "ӏ": "l", "Ꭺ": "A", "Ᏼ": "B", "Ꮯ": "C",
    "ℓ": "l", "ꓲ": "I", "ǀ": "l", "ο": "o", "ᴏ": "o", "ᴄ": "c",
}
# (duplicate keys in the literal above collapse harmlessly; this check keeps the table honest)
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})
B64 = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
HEX = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
SPACED = re.compile(r"(?:(?<=\s)|^)(?:\S ){5,}\S(?=\s|$)")


def strip_invisible(s: str) -> str:
    """Format characters (zero-width, soft hyphen, bidi, tags) are deleted; other control characters become
    a SPACE (deleting NUL/VT/FF would glue 'UNION\\x00SELECT' into one word and hide the boundary)."""
    out = []
    for c in s:
        cat = unicodedata.category(c)
        if cat == "Cf":
            continue
        out.append(" " if cat == "Cc" and c not in "\n\t\r" else c)
    return "".join(out)


def fold_keep_ws(s: str) -> str:
    """NFKC + drop invisibles + fold look-alikes, WITHOUT touching whitespace (newlines matter to injection checks)."""
    s = unicodedata.normalize("NFKC", s)
    s = strip_invisible(s)
    return "".join(CONFUSABLES.get(c, c) for c in s)


def fold(s: str) -> str:
    return re.sub(r"\s+", " ", fold_keep_ws(s)).strip()


SPACED_RUN = re.compile(r"(?<![^\s])(?:[^\s] ){2,}[^\s](?![^\s])")   # runs of single characters separated by ONE space


def _despace(s: str) -> str:
    """'i g n o r e   a l l' -> 'ignore all': join single-char runs but keep the (wider) word gaps."""
    return SPACED_RUN.sub(lambda m: m.group(0).replace(" ", ""), s)


def _printable(b: bytes) -> str | None:
    try:
        t = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return t if len(t) >= 6 and sum(c.isprintable() or c in "\n\t" for c in t) / len(t) > 0.95 else None


def variants(text: str, depth: int = 2) -> list[tuple[str, str]]:
    """(label, text) readings of `text`: the folded original plus decoded / de-obfuscated forms."""
    base = fold(text)
    seen = {base}
    out = [("plain", base)]

    def add(label: str, t: str) -> None:
        t = fold(t)
        if t and t not in seen:
            seen.add(t)
            out.append((label, t))

    kept = fold_keep_ws(text)
    add("despaced", _despace(re.sub(r"[ \t]{2,}", "  ", kept)))
    nomarks = unicodedata.normalize("NFC", "".join(c for c in unicodedata.normalize("NFKD", kept)
                                                    if unicodedata.category(c) != "Mn"))
    add("marks-stripped", nomarks)
    add("html-unescaped", html.unescape(base))
    add("escape-decoded", re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), base))
    sep = re.sub(r"[^\w\s]+|_+", " ", kept)                    # ignore-all-previous / i.g.n.o.r.e / under_scores
    add("separators-as-spaces", _despace(re.sub(r"[ \t]{2,}", "  ", sep)))
    add("reversed-words", " ".join(w[::-1] for w in base.split()))
    add("reversed-text", base[::-1])
    add("leetspeak", base.translate(LEET))
    add("rot13", codecs.decode(base, "rot13"))
    add("percent-decoded", urllib.parse.unquote_plus(base))
    for lab, v in list(out)[1:]:                       # one extra layer: transformations composed (leet then rot13, ...)
        add(f"{lab}>leetspeak", v.translate(LEET))
        add(f"{lab}>rot13", codecs.decode(v, "rot13"))
        add(f"{lab}>despaced", _despace(v))
    if depth > 0:
        for m in B64.findall(base):
            for fn in (base64.b64decode, base64.urlsafe_b64decode):
                try:
                    t = _printable(fn(m + "=" * (-len(m) % 4)))
                except (binascii.Error, ValueError):
                    continue
                if t:
                    add("base64-decoded", t)
                    for lab, v in variants(t, depth - 1)[1:]:
                        add(f"base64>{lab}", v)
                    break
        for m in HEX.findall(base):
            try:
                t = _printable(bytes.fromhex(m))
            except ValueError:
                continue
            if t:
                add("hex-decoded", t)
    return out
