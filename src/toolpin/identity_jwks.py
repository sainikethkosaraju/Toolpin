"""Resource-server token validation with JWKS (RS256 / ES256) plus RFC 9728 / RFC 8707 plumbing.

Strict by construction: the algorithm comes from an ALLOW-LIST (never from the token alone, so `none` and
HS256-with-the-public-key confusion are impossible), the key from the JWKS by `kid`, and the audience must
equal THIS resource's identifier (RFC 8707). Not an authorization server."""
from __future__ import annotations

import base64
import json
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from toolpin.identity import IdentityError


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _int(s: str) -> int:
    return int.from_bytes(_unb64(s), "big")


def jwk_to_key(jwk: Mapping[str, Any]):
    kty = jwk.get("kty")
    if kty == "RSA":
        return rsa.RSAPublicNumbers(_int(jwk["e"]), _int(jwk["n"])).public_key()
    if kty == "EC" and jwk.get("crv") == "P-256":
        return ec.EllipticCurvePublicNumbers(_int(jwk["x"]), _int(jwk["y"]), ec.SECP256R1()).public_key()
    raise IdentityError(f"unsupported key type {kty!r}")


class JWKSVerifier:
    def __init__(self, jwks: Mapping[str, Any] | Callable[[], Mapping[str, Any]], resource: str,
                 issuers: set[str], algorithms: tuple[str, ...] = ("RS256", "ES256"), leeway: float = 30.0,
                 required_scopes: tuple[str, ...] = (), clock: Callable[[], float] = time.time,
                 replay_cache: int = 10_000) -> None:
        self._jwks, self.resource, self.issuers = jwks, resource, issuers
        self.algorithms, self.leeway, self.required_scopes, self.clock = algorithms, leeway, required_scopes, clock
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._cap = replay_cache

    def _keys(self) -> list[Mapping[str, Any]]:
        j = self._jwks() if callable(self._jwks) else self._jwks
        return list(j.get("keys", []))

    def verify(self, token: str, single_use: bool = False) -> dict[str, Any]:
        try:
            h_s, p_s, s_s = token.split(".")
            header, claims, sig = json.loads(_unb64(h_s)), json.loads(_unb64(p_s)), _unb64(s_s)
        except Exception:
            raise IdentityError("malformed token") from None
        alg = header.get("alg")
        if alg not in self.algorithms:
            raise IdentityError("algorithm not allowed")
        kid = header.get("kid")
        cands = [k for k in self._keys() if k.get("kid") == kid] if kid else []
        if len(cands) != 1:
            raise IdentityError("unknown or ambiguous key id")
        jwk = cands[0]
        if jwk.get("alg") not in (None, alg) or jwk.get("use") not in (None, "sig"):
            raise IdentityError("key not usable for this algorithm")
        key = jwk_to_key(jwk)
        signed = f"{h_s}.{p_s}".encode()
        try:
            if alg == "RS256":
                if not isinstance(key, rsa.RSAPublicKey):
                    raise IdentityError("key type does not match algorithm")
                key.verify(sig, signed, padding.PKCS1v15(), hashes.SHA256())
            else:  # ES256: raw r||s (RFC 7518) -> DER
                if not isinstance(key, ec.EllipticCurvePublicKey) or len(sig) != 64:
                    raise IdentityError("key type does not match algorithm")
                key.verify(utils.encode_dss_signature(int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")),
                           signed, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature:
            raise IdentityError("bad signature") from None
        now = self.clock()
        if claims.get("iss") not in self.issuers:
            raise IdentityError("untrusted issuer")
        aud = claims.get("aud")
        if self.resource not in ([aud] if isinstance(aud, str) else aud if isinstance(aud, list) else []):
            raise IdentityError("token not issued for this resource (audience)")
        exp = claims.get("exp")
        if not isinstance(exp, int | float) or now > exp + self.leeway:
            raise IdentityError("expired or missing exp")
        if isinstance(claims.get("nbf"), int | float) and now + self.leeway < claims["nbf"]:
            raise IdentityError("not yet valid")
        if not isinstance(claims.get("sub"), str) or not claims["sub"]:
            raise IdentityError("missing subject")
        have = set(str(claims.get("scope", "")).split()) | set(claims.get("scp", []) if isinstance(claims.get("scp"), list) else [])
        if not set(self.required_scopes) <= have:
            raise IdentityError("missing required scope")
        if single_use:
            jti = claims.get("jti")
            if not isinstance(jti, str):
                raise IdentityError("single-use verification needs a jti")
            self._seen = OrderedDict((j, e) for j, e in self._seen.items() if e > now)
            if jti in self._seen:
                raise IdentityError("token replay")
            self._seen[jti] = exp + self.leeway
            while len(self._seen) > self._cap:
                self._seen.popitem(last=False)
        return claims


def protected_resource_metadata(resource: str, authorization_servers: list[str], scopes: list[str]) -> dict[str, Any]:
    """RFC 9728 document served at /.well-known/oauth-protected-resource."""
    return {"resource": resource, "authorization_servers": authorization_servers, "scopes_supported": scopes,
            "bearer_methods_supported": ["header"]}


def www_authenticate(resource_metadata_url: str, error: str | None = None, scope: str | None = None) -> str:
    parts = [f'resource_metadata="{resource_metadata_url}"']
    if error:
        parts.insert(0, f'error="{error}"')
    if scope:
        parts.append(f'scope="{scope}"')
    return "Bearer " + ", ".join(parts)
