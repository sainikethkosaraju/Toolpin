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
import sqlite3
import threading
import time
from collections.abc import Callable
from typing import Protocol

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


class NonceStore(Protocol):
    def consume(self, nonce: str, exp: float, now: float) -> bool:
        """Atomically record `nonce`; True only the FIRST time (and only if not already expired)."""
        ...


class MemoryNonceStore:
    def __init__(self) -> None:
        self._used: dict[str, float] = {}
        self._lock = threading.Lock()

    def consume(self, nonce: str, exp: float, now: float) -> bool:
        with self._lock:
            self._used = {n: e for n, e in self._used.items() if e >= now}
            if nonce in self._used:
                return False
            self._used[nonce] = exp
            return True


class SQLiteNonceStore:
    """Durable, multi-process replay protection: the PRIMARY KEY makes consumption atomic across workers
    that share the file (WAL mode, `INSERT OR IGNORE`). Expired nonces are purged opportunistically."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._local = threading.local()
        self._conn().execute("CREATE TABLE IF NOT EXISTS nonces(nonce TEXT PRIMARY KEY, exp REAL NOT NULL)")

    def _conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "c", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=30, isolation_level=None)
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA busy_timeout=30000")
            self._local.c = c
        return c

    def consume(self, nonce: str, exp: float, now: float) -> bool:
        c = self._conn()
        c.execute("DELETE FROM nonces WHERE exp < ?", (now,))
        cur = c.execute("INSERT OR IGNORE INTO nonces VALUES(?, ?)", (nonce, exp))
        return cur.rowcount == 1


class Approvals:
    """Keys: a single secret, or a rotation ring `[(kid, secret), ...]`: the FIRST key signs, every key
    verifies, and a token naming an unknown kid is rejected. Rotate by prepending the new key, waiting one
    TTL, then dropping the old one."""

    def __init__(self, secret: str | bytes | list[tuple[str, str | bytes]], ttl: float = 300.0,
                 clock: Callable[[], float] = time.time, nonces: NonceStore | None = None) -> None:
        ring = secret if isinstance(secret, list) else [("0", secret)]
        self._keys: dict[str, bytes] = {}
        for kid, k in ring:
            key = k.encode() if isinstance(k, str) else k
            if len(key) < MIN_SECRET:
                raise ValueError(f"approval secret must be at least {MIN_SECRET} bytes")
            self._keys[str(kid)] = key
        self._sign_kid = str(ring[0][0])
        self.ttl, self.clock = ttl, clock
        self.nonces: NonceStore = nonces or MemoryNonceStore()

    def _sig(self, kid: str, payload: bytes) -> bytes:
        return hmac.new(self._keys[kid], b"toolpin-approval-v1." + payload, hashlib.sha256).digest()

    def issue(self, principal: str, tool: str, arguments: dict | None) -> str:
        body = json.dumps({"p": principal, "t": tool, "a": args_hash(arguments), "n": secrets.token_hex(16),
                           "e": self.clock() + self.ttl, "k": self._sign_kid},
                          sort_keys=True, separators=(",", ":")).encode()
        return f"{_b64(body)}.{_b64(self._sig(self._sign_kid, body))}"

    def redeem(self, token: str, principal: str, tool: str, arguments: dict | None) -> None:
        """Raises ApprovalError unless the token is authentic, unexpired, unused and bound to exactly this
        principal, tool and canonical arguments. The nonce is consumed only after every other check passes."""
        try:
            body_s, sig_s = token.split(".")
            body, sig = _unb64(body_s), _unb64(sig_s)
            claims = json.loads(body)
            kid = str(claims.get("k", "0"))
        except Exception:
            raise ApprovalError("malformed") from None
        if kid not in self._keys:
            raise ApprovalError("unknown key id")
        if not hmac.compare_digest(sig, self._sig(kid, body)):
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
        if not self.nonces.consume(str(claims.get("n")), float(claims["e"]), now):
            raise ApprovalError("replay")
