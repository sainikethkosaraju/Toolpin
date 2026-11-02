"""Resource-server identity checks: audience binding, no token passthrough, handle binding.

Full OAuth is out of scope. `verify_hs256_jwt` is a minimal, strict verifier for shared-secret
deployments; production servers should use their IdP's JWKS verification and then call
`validate_claims` on the verified claims."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from collections.abc import Mapping
from typing import Any


class IdentityError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__("invalid credentials")
        self.reason = reason


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_hs256_jwt(token: str, key: bytes) -> dict[str, Any]:
    try:
        h_s, p_s, s_s = token.split(".")
        header = json.loads(_unb64(h_s))
        claims = json.loads(_unb64(p_s))
        sig = _unb64(s_s)
    except Exception:
        raise IdentityError("malformed token") from None
    if header.get("alg") != "HS256":  # rejects alg=none and algorithm confusion
        raise IdentityError("unsupported alg")
    good = hmac.new(key, f"{h_s}.{p_s}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(sig, good):
        raise IdentityError("bad signature")
    return claims


def validate_claims(claims: Mapping[str, Any], audience: str, trusted_issuers: set[str],
                    now: float | None = None) -> str:
    """Return the subject, or raise. The token must be minted FOR THIS server (audience)."""
    now = time.time() if now is None else now
    aud = claims.get("aud")
    auds = [aud] if isinstance(aud, str) else list(aud) if isinstance(aud, list) else []
    if audience not in auds:
        raise IdentityError("wrong or missing audience")
    if claims.get("iss") not in trusted_issuers:
        raise IdentityError("untrusted issuer")
    exp = claims.get("exp")
    if not isinstance(exp, int | float) or now >= exp:
        raise IdentityError("expired or missing exp")
    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub:
        raise IdentityError("missing subject")
    return sub


def assert_no_passthrough(outgoing_headers: Mapping[str, str], inbound_token: str) -> None:
    """Never forward the client's token upstream (confused deputy). Raises if it appears."""
    for k, v in outgoing_headers.items():
        if inbound_token and inbound_token in v:
            raise IdentityError(f"inbound token forwarded in header {k}")


class HandleBinder:
    """Binds opaque state handles (cursors, task ids) to a principal and expiry with HMAC, so a
    guessed, reused-by-another-principal or tampered handle is rejected."""

    def __init__(self, secret: bytes, ttl: float = 600.0, clock=time.time) -> None:
        if len(secret) < 32:
            raise ValueError("secret must be >= 32 bytes")
        self._k, self.ttl, self.clock = secret, ttl, clock

    def _mac(self, handle: str, principal: str, exp: int) -> str:
        msg = json.dumps([handle, principal, exp]).encode()
        return hmac.new(self._k, b"toolpin-handle-v1." + msg, hashlib.sha256).hexdigest()

    def bind(self, handle: str, principal: str) -> str:
        exp = int(self.clock() + self.ttl)
        return f"{handle}.{exp}.{self._mac(handle, principal, exp)}"

    def check(self, bound: str, principal: str) -> str:
        try:
            handle, exp_s, mac = bound.rsplit(".", 2)
            exp = int(exp_s)
        except ValueError:
            raise IdentityError("malformed handle") from None
        if not hmac.compare_digest(mac, self._mac(handle, principal, exp)):
            raise IdentityError("handle not bound to this principal")
        if self.clock() > exp:
            raise IdentityError("handle expired")
        return handle
