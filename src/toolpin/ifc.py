"""Information-flow control for agent tool use.

The "lethal trifecta": an agent that can (1) read PRIVATE data, (2) ingest UNTRUSTED content, and
(3) communicate EXTERNALLY can be tricked into leaking. Per-call policy cannot see this: every
single call looks fine. IFC adds session memory:

  * labels on tools: `private` (output may contain sensitive data), `untrusted` (output is attacker-
    influenced), `egress` (arguments can leave the trust boundary);
  * session state: has private data been seen? has untrusted content been seen?
  * rule 1 (trifecta): an egress call in a session that has seen BOTH is denied or escalated to a
    human approval (configurable);
  * rule 2 (value flow): an egress call whose arguments CONTAIN data fingerprinted from a private
    output is denied, whatever the session flags say. Fingerprints are salted HMACs of
    identifier-like atoms and word shingles, so the taint store never keeps raw secrets, and
    base64 / hex / percent-encoded copies in arguments are decoded before matching.

LIMITS (stated plainly): rule 2 does not see paraphrase, summarisation, translation or any lossy
re-expression, nor covert channels (timing, argument ordering). That is exactly why rule 1 exists.
Atoms must look like identifiers (digits, @, long, mixed) or be figures with >= 5 significant digits (so
48215.0 matches 48,215), to keep false positives down; plain prose is only caught through 5-word shingles."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import re
import urllib.parse
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Literal

Kind = Literal["allow", "deny", "require_approval"]

ATOM = re.compile(r"[A-Za-z0-9_.@+\-/:=]{8,}")
WORD = re.compile(r"[A-Za-z0-9']+")
B64 = re.compile(r"(?:[A-Za-z0-9+/]{16,}={0,2})|(?:[A-Za-z0-9_-]{16,})")
HEX = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
SHINGLE = 5
NUMBER = re.compile(r"\d[\d,]*(?:\.\d+)?")
MIN_SIGNIFICANT_DIGITS = 5


@dataclass(frozen=True)
class ToolLabels:
    private: bool = False
    untrusted: bool = False
    egress: bool = False
    egress_args: tuple[str, ...] | None = None  # None = every argument leaves; else only these


@dataclass
class IFCConfig:
    tools: dict[str, ToolLabels] = field(default_factory=dict)
    trifecta: Kind = "require_approval"
    value_flow: Kind = "deny"
    max_fingerprints: int = 200_000


@dataclass(frozen=True)
class Verdict:
    kind: Kind
    rule: str = ""
    reason: str = ""


ALLOW = Verdict("allow")


@dataclass
class Session:
    private_exposed: bool = False
    untrusted_exposed: bool = False
    fingerprints: OrderedDict[str, None] = field(default_factory=OrderedDict)
    events: list[str] = field(default_factory=list)


def _identifier_like(tok: str) -> bool:
    return bool(re.search(r"\d", tok) or re.search(r"[@_\-/:=+.]", tok) or len(tok) >= 14)


def _pieces(tok: str) -> set[str]:
    """A token and its sub-identifiers: `api_key=sk-live-4f9a...` also yields `sk-live-4f9a...` and
    `4f9a...`, because the same secret is quoted with different surrounding context."""
    tok = tok.strip(".,;:")
    out = {tok}
    for p in re.split(r"[=:/]", tok):
        p = p.strip(".,;:")
        out.add(p)
        if re.search(r"\d", p):
            out.update(q for q in re.split(r"[-_]", p) if len(q) >= 8)
    return out


def _decoded_variants(text: str) -> list[str]:
    """The text plus plausible decodings (percent, base64/base64url, hex) found inside it."""
    out = [text]
    try:
        u = urllib.parse.unquote_plus(text)
        if u != text:
            out.append(u)
    except Exception:
        pass
    for m in B64.findall(text):
        for fn in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                raw = fn(m + "=" * (-len(m) % 4))
                s = raw.decode("utf-8")
                if s.isprintable() and len(s) >= 6:
                    out.append(s)
                    break
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
    for m in HEX.findall(text):
        try:
            s = bytes.fromhex(m).decode("utf-8")
            if s.isprintable():
                out.append(s)
        except (ValueError, UnicodeDecodeError):
            continue
    return out


def _leaves(o: Any) -> list[str]:
    if isinstance(o, str):
        return [o]
    if isinstance(o, bool) or o is None:
        return []
    if isinstance(o, int | float):
        return [str(o)]
    if isinstance(o, dict):
        return [x for k, v in o.items() for x in [*_leaves(str(k)), *_leaves(v)]]
    if isinstance(o, list | tuple):
        return [x for v in o for x in _leaves(v)]
    return [str(o)]


class IFC:
    def __init__(self, config: IFCConfig, secret: bytes) -> None:
        if len(secret) < 16:
            raise ValueError("IFC secret must be at least 16 bytes")
        self.cfg, self._key = config, secret
        self.sessions: dict[str, Session] = {}

    # ------------------------------------------------------------------ fingerprints
    def _fp(self, s: str) -> str:
        return hmac.new(self._key, s.lower().encode(), hashlib.sha256).hexdigest()[:24]

    def atoms(self, text: str) -> set[str]:
        out: set[str] = set()
        for variant in _decoded_variants(text):
            for tok in ATOM.findall(variant):
                for piece in _pieces(tok):
                    if len(piece) >= 8 and _identifier_like(piece):
                        out.add("a:" + self._fp(piece))
            for num in NUMBER.findall(variant):                      # figures: 48215.0 == 48,215 == 48215.00
                canon = num.replace(",", "")
                canon = canon.rstrip("0").rstrip(".") if "." in canon else canon
                if len(canon.replace(".", "").lstrip("0")) >= MIN_SIGNIFICANT_DIGITS:
                    out.add("n:" + self._fp(canon))
            words = [w.lower() for w in WORD.findall(variant)]
            for i in range(len(words) - SHINGLE + 1):
                out.add("s:" + self._fp(" ".join(words[i:i + SHINGLE])))
        return out

    # ------------------------------------------------------------------ session state
    def session(self, sid: str) -> Session:
        return self.sessions.setdefault(sid, Session())

    def labels(self, tool: str) -> ToolLabels:
        return self.cfg.tools.get(tool, ToolLabels())

    def observe_result(self, sid: str, tool: str, text: str) -> None:
        lab, s = self.labels(tool), self.session(sid)
        if lab.private:
            s.private_exposed = True
            for a in self.atoms(text):
                s.fingerprints[a] = None
            while len(s.fingerprints) > self.cfg.max_fingerprints:
                s.fingerprints.popitem(last=False)
            s.events.append(f"private data read via {tool}")
        if lab.untrusted:
            s.untrusted_exposed = True
            s.events.append(f"untrusted content via {tool}")

    def check_call(self, sid: str, tool: str, arguments: dict[str, Any]) -> Verdict:
        lab = self.labels(tool)
        if not lab.egress:
            return ALLOW
        s = self.session(sid)
        leaving = arguments if lab.egress_args is None else {k: v for k, v in arguments.items() if k in lab.egress_args}
        if s.fingerprints:
            seen = self.atoms(" ".join(_leaves(leaving)))
            hits = seen & set(s.fingerprints)
            if hits:
                return Verdict(self.cfg.value_flow, "ifc-value-flow",
                               f"{len(hits)} fragment(s) of previously read private data appear in the arguments")
        if s.private_exposed and s.untrusted_exposed:
            return Verdict(self.cfg.trifecta, "ifc-trifecta",
                           "session has read private data AND ingested untrusted content; external communication needs approval")
        return ALLOW
