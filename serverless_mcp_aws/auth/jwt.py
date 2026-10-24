"""JWT access-token verification against a JWKS URL.

Hard rules, none of them configurable away:

* Only asymmetric algorithms from a fixed safe set (RS256, ES256). `none` and
  every HMAC algorithm are refused before any key is looked up, so an
  attacker cannot sign an HS256 token with the server's *public* key.
* The algorithm comes from the server's allowlist, never from the token: the
  token's `alg` must be in the allowlist and must match the key type (an RSA
  key never verifies an ES256 token, and vice versa).
* Keys come only from the configured JWKS URL. Header parameters that point
  elsewhere or embed a key (`jku`, `jwk`, `x5u`, `x5c`) and `crit` extensions
  are refused.
* `exp`, `iss`, `aud` and `sub` are required; `nbf` and `iat` are checked when
  present. The audience must be this server (RFC 8707 resource indicator).
* Size limits on the token and the JWKS document; an unknown `kid` refreshes
  the JWKS at most once per `min_refresh_interval`, so random kids cannot make
  the function hammer the identity provider.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import logging
import os
import ssl
import threading
import time
from collections.abc import Callable
from collections.abc import Iterable
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any
from typing import Final
from urllib.parse import urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa

from serverless_mcp_aws.auth.principal import Principal

__all__ = [
    "SAFE_ALGORITHMS",
    "InvalidToken",
    "JWKSCache",
    "JWTVerifier",
    "fetch_url",
]

logger = logging.getLogger(__name__)

SAFE_ALGORITHMS: Final = frozenset({"RS256", "ES256"})
_KEY_TYPE: Final = {"RS256": "RSA", "ES256": "EC"}
_FORBIDDEN_HEADERS: Final = frozenset({"jku", "jwk", "x5u", "x5c", "crit"})
_ALLOWED_TYP: Final = frozenset({"jwt", "at+jwt", "application/at+jwt"})
MIN_RSA_BITS: Final = 2048


class InvalidToken(Exception):
    """The bearer token was refused.

    `reason` is one of a fixed set of short strings (safe to put in a
    `WWW-Authenticate` header); it never echoes token content.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


Fetcher = Callable[[str], bytes]


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def fetch_url(url: str, *, timeout: float = 3.0, max_bytes: int = 64 * 1024) -> bytes:
    """GET `url` and return the body. HTTPS only (plain HTTP only to loopback).

    No redirects are followed and the body is capped at `max_bytes`.
    """
    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.scheme == "https":
        conn: http.client.HTTPConnection = http.client.HTTPSConnection(
            host, parts.port, timeout=timeout, context=ssl.create_default_context()
        )
    elif parts.scheme == "http" and _is_loopback(host):
        conn = http.client.HTTPConnection(host, parts.port, timeout=timeout)
    else:
        raise ValueError("JWKS URL must be https (http is allowed for loopback only)")
    target = parts.path or "/"
    if parts.query:
        target = f"{target}?{parts.query}"
    try:
        conn.request("GET", target, headers={"Accept": "application/json"})
        resp = conn.getresponse()
        if resp.status != 200:
            raise OSError(f"JWKS fetch returned HTTP {resp.status}")
        body = resp.read(max_bytes + 1)
    finally:
        conn.close()
    if len(body) > max_bytes:
        raise OSError("JWKS document too large")
    return body


def _validate_url(url: str, what: str) -> str:
    parts = urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return url
    if parts.scheme == "http" and _is_loopback(parts.hostname or ""):
        return url
    raise ValueError(f"{what} must be an https URL (http only for loopback): {url!r}")


@dataclass(frozen=True)
class _Key:
    kid: str | None
    kty: str
    alg: str | None
    key: Any


def _parse_jwks(raw: bytes) -> list[_Key]:
    try:
        doc = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as exc:
        raise OSError("JWKS is not JSON") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list):
        raise OSError("JWKS has no keys array")
    keys: list[_Key] = []
    for entry in doc["keys"]:
        if not isinstance(entry, dict):
            continue
        kty = entry.get("kty")
        if kty not in ("RSA", "EC"):
            continue  # oct (symmetric) and OKP keys are never used
        if entry.get("use", "sig") != "sig":
            continue
        alg = entry.get("alg")
        if alg is not None and alg not in SAFE_ALGORITHMS:
            continue
        if any(name in entry for name in ("d", "p", "q", "dp", "dq", "qi", "k")):
            continue  # a private or secret key in a public JWKS: refuse to use it
        try:
            pyjwk = jwt.PyJWK.from_dict(entry, algorithm="RS256" if kty == "RSA" else "ES256")
        except (jwt.PyJWKError, jwt.InvalidKeyError, ValueError, TypeError):
            continue
        key = pyjwk.key
        if isinstance(key, rsa.RSAPublicKey):
            if key.key_size < MIN_RSA_BITS:
                continue
        elif isinstance(key, ec.EllipticCurvePublicKey):
            if not isinstance(key.curve, ec.SECP256R1):
                continue
        else:
            continue
        kid = entry.get("kid")
        keys.append(_Key(kid=kid if isinstance(kid, str) else None, kty=kty, alg=alg, key=key))
    return keys


class JWKSCache:
    """A thread-safe JWKS cache with TTL and a refresh rate limit."""

    def __init__(
        self,
        url: str,
        *,
        ttl: float = 600.0,
        min_refresh_interval: float = 60.0,
        fetcher: Fetcher | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.url = _validate_url(url, "jwks_url")
        self.ttl = ttl
        self.min_refresh_interval = min_refresh_interval
        self._fetch: Fetcher = fetcher or fetch_url
        self._clock = clock
        self._lock = threading.Lock()
        self._keys: list[_Key] = []
        self._fetched_at: float | None = None

    def _refresh_locked(self) -> None:
        now = self._clock()
        if self._fetched_at is not None and now - self._fetched_at < self.min_refresh_interval:
            return
        try:
            self._keys = _parse_jwks(self._fetch(self.url))
        except (OSError, ValueError) as exc:
            # Keep serving the keys we had (if any); never log the document.
            logger.warning("JWKS refresh failed: %s", type(exc).__name__)
        finally:
            self._fetched_at = now

    def keys(self, *, force: bool = False) -> list[_Key]:
        with self._lock:
            stale = (
                self._fetched_at is None
                or not self._keys
                or self._clock() - self._fetched_at >= self.ttl
            )
            if force or stale:
                self._refresh_locked()
            return list(self._keys)

    def find(self, kid: str | None, alg: str) -> Any:
        """The public key for `kid` usable with `alg`, refreshing once for an unknown kid."""
        for attempt in (False, True):
            candidates = [
                k
                for k in self.keys(force=attempt)
                if k.kty == _KEY_TYPE[alg] and (k.alg is None or k.alg == alg)
            ]
            if kid is None:
                # Without a kid only an unambiguous JWKS is acceptable.
                if len(candidates) == 1:
                    return candidates[0].key
                if candidates:
                    raise InvalidToken("token has no kid")
            else:
                for k in candidates:
                    if k.kid == kid:
                        return k.key
        raise InvalidToken("unknown signing key")


class JWTVerifier:
    """Verifies RS256/ES256 access tokens issued by one authorization server."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: str | Iterable[str],
        jwks_url: str,
        algorithms: Iterable[str] = ("RS256", "ES256"),
        leeway: float = 30.0,
        max_token_bytes: int = 8192,
        jwks_ttl: float = 600.0,
        jwks_min_refresh_interval: float = 60.0,
        require_typ: bool = False,
        fetcher: Fetcher | None = None,
    ) -> None:
        if not issuer:
            raise ValueError("issuer is required")
        algs = frozenset(algorithms)
        if not algs:
            raise ValueError("at least one algorithm is required")
        unsafe = algs - SAFE_ALGORITHMS
        if unsafe:
            raise ValueError(
                f"refusing algorithms {sorted(unsafe)}: only {sorted(SAFE_ALGORITHMS)} are allowed"
            )
        self.issuer = issuer
        self.audience: tuple[str, ...] = (
            (audience,) if isinstance(audience, str) else tuple(audience)
        )
        if not self.audience or not all(self.audience):
            raise ValueError("audience is required (the MCP server's canonical URI)")
        self.algorithms = algs
        self.leeway = leeway
        self.max_token_bytes = max_token_bytes
        self.require_typ = require_typ
        self.jwks = JWKSCache(
            jwks_url, ttl=jwks_ttl, min_refresh_interval=jwks_min_refresh_interval, fetcher=fetcher
        )

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> JWTVerifier:
        """Build from environment variables (see the README configuration table).

        `MCP_JWT_ISSUER` and `MCP_JWT_JWKS_URL` are required; `MCP_JWT_ALGORITHMS`
        defaults to `RS256,ES256`.

        `MCP_JWT_AUDIENCE` defaults to `MCP_RESOURCE`.
        """
        env = os.environ if env is None else env
        try:
            issuer = env["MCP_JWT_ISSUER"]
            jwks_url = env["MCP_JWT_JWKS_URL"]
        except KeyError as exc:
            raise ValueError(f"missing environment variable {exc.args[0]}") from None
        audience = env.get("MCP_JWT_AUDIENCE") or env.get("MCP_RESOURCE", "")
        algorithms = env.get("MCP_JWT_ALGORITHMS", "RS256,ES256")
        return cls(
            issuer=issuer,
            audience=[a.strip() for a in audience.split(",") if a.strip()],
            jwks_url=jwks_url,
            algorithms=[a.strip() for a in algorithms.split(",") if a.strip()],
        )

    def verify(self, token: str) -> Principal:
        """Return the token's principal or raise `InvalidToken`."""
        if not token or len(token) > self.max_token_bytes:
            raise InvalidToken("token too large" if token else "missing token")
        if token.count(".") != 2:
            raise InvalidToken("malformed token")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:  # undecodable, or a `crit` extension PyJWT does not support
            raise InvalidToken("malformed token") from None
        alg = header.get("alg")
        if not isinstance(alg, str) or alg not in self.algorithms:
            raise InvalidToken("algorithm not allowed")
        if _FORBIDDEN_HEADERS & set(header):
            raise InvalidToken("forbidden token header")
        typ = header.get("typ")
        if typ is not None and (not isinstance(typ, str) or typ.lower() not in _ALLOWED_TYP):
            raise InvalidToken("wrong token type")
        if self.require_typ and (not isinstance(typ, str) or typ.lower() == "jwt"):
            raise InvalidToken("wrong token type")
        kid = header.get("kid")
        if kid is not None and (not isinstance(kid, str) or len(kid) > 256):
            raise InvalidToken("malformed token")

        key = self.jwks.find(kid, alg)
        try:
            claims = jwt.decode(
                token,
                key=key,
                algorithms=[alg],
                audience=list(self.audience),
                issuer=self.issuer,
                leeway=self.leeway,
                options={
                    "require": ["exp", "iss", "aud", "sub"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_aud": True,
                    "verify_iss": True,
                },
            )
        except jwt.ExpiredSignatureError:
            raise InvalidToken("token expired") from None
        except jwt.ImmatureSignatureError:
            raise InvalidToken("token not yet valid") from None
        except jwt.InvalidAudienceError:
            raise InvalidToken("invalid audience") from None
        except jwt.InvalidIssuerError:
            raise InvalidToken("invalid issuer") from None
        except jwt.MissingRequiredClaimError:
            raise InvalidToken("missing required claim") from None
        except jwt.InvalidSignatureError:
            raise InvalidToken("invalid signature") from None
        except jwt.PyJWTError:
            raise InvalidToken("invalid token") from None
        return principal_from_claims(claims)


def _scopes(claims: Mapping[str, Any]) -> frozenset[str]:
    raw = claims.get("scope", claims.get("scp"))
    if isinstance(raw, str):
        return frozenset(raw.split())
    if isinstance(raw, list):
        return frozenset(s for s in raw if isinstance(s, str) and s and " " not in s)
    return frozenset()


def principal_from_claims(claims: Mapping[str, Any]) -> Principal:
    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub:
        raise InvalidToken("missing required claim")
    aud = claims.get("aud")
    audience = (aud,) if isinstance(aud, str) else tuple(a for a in aud or () if isinstance(a, str))
    client_id = claims.get("client_id", claims.get("azp", ""))
    exp = claims.get("exp")
    return Principal(
        subject=sub,
        issuer=str(claims.get("iss", "")),
        client_id=client_id if isinstance(client_id, str) else "",
        scopes=_scopes(claims),
        expires_at=int(exp) if isinstance(exp, int | float) else None,
        audience=audience,
        claims=MappingProxyType(dict(claims)),
    )
