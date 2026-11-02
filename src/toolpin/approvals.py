"""Call-bound approvals.

A token is HMAC-SHA256 over {principal, tool, args_hash, nonce, exp}. It is valid for ONE exact
call: other arguments, other tool, other principal, a second use, or an expired token are all
rejected. The secret must be >= 32 bytes and has no default."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from collections.abc import Callable

from toolpin.canonical import args_hash

MIN_SECRET = 32


class ApprovalError(Exception):
    """Rejected approval. `reason` is for the audit log only; callers show a generic message."""

    def __init__(self, reason: str) -> None:
        super().__init__("approval rejected")
        self.reason = reason


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if _b64(raw) != s:
        raise ValueError("non-canonical base64")
    return raw


class Approvals:
    def __init__(self, secret: str | bytes, ttl: float = 300.0,
                 clock: Callable[[], float] = time.time) -> None:
        key = secret.encode() if isinstance(secret, str) else secret
        if len(key) < MIN_SECRET:
            raise ValueError(f"approval secret must be at least {MIN_SECRET} bytes")
        self._key, self.ttl, self.clock = key, ttl, clock
        self._used: dict[str, float] = {}  # nonce -> exp

    def _sig(self, payload: bytes) -> bytes:
        return hmac.new(self._key, b"toolpin-approval-v1." + payload, hashlib.sha256).digest()

    def issue(self, principal: str, tool: str, arguments: dict | None) -> str:
        body = json.dumps({"p": principal, "t": tool, "a": args_hash(arguments),
                           "n": secrets.token_hex(16), "e": self.clock() + self.ttl},
                          sort_keys=True, separators=(",", ":")).encode()
        return f"{_b64(body)}.{_b64(self._sig(body))}"

    def redeem(self, token: str, principal: str, tool: str, arguments: dict | None) -> None:
        """Raises ApprovalError unless the token is authentic, unexpired, unused and bound to
        exactly this principal, tool and canonical arguments. The nonce is consumed only on success."""
        try:
            body_s, sig_s = token.split(".")
            body, sig = _unb64(body_s), _unb64(sig_s)
            claims = json.loads(body)
        except Exception:
            raise ApprovalError("malformed") from None
        if not hmac.compare_digest(sig, self._sig(body)):
            raise ApprovalError("bad signature")
        now = self.clock()
        if not isinstance(claims.get("e"), int | float) or now > claims["e"]:
            raise ApprovalError("expired")
        if not hmac.compare_digest(str(claims.get("p")), principal):
            raise ApprovalError("wrong principal")
        if claims.get("t") != tool:
            raise ApprovalError("wrong tool")
        if not hmac.compare_digest(str(claims.get("a")), args_hash(arguments)):
            raise ApprovalError("arguments changed")
        nonce = str(claims.get("n"))
        self._used = {n: e for n, e in self._used.items() if e >= now}  # forget expired nonces
        if nonce in self._used:
            raise ApprovalError("replay")
        self._used[nonce] = float(claims["e"])
