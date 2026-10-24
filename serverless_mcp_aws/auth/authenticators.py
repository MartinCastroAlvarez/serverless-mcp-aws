"""How the handler learns who is calling.

* `BearerAuth` verifies the `Authorization: Bearer` token inside the MCP
  function (spec-compliant 401/403 challenges with `resource_metadata`).
* `AuthorizerContextAuth` trusts what an API Gateway authorizer already
  verified: the context a Lambda authorizer returned (see
  `serverless_mcp_aws.authorizer`) or the claims of API Gateway's built-in JWT
  authorizer. API Gateway writes `requestContext.authorizer`; a client cannot.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any
from typing import Literal
from typing import Protocol

from serverless_mcp_aws.auth.jwt import InvalidToken
from serverless_mcp_aws.auth.jwt import JWTVerifier
from serverless_mcp_aws.auth.principal import Principal
from serverless_mcp_aws.events import HttpRequest

__all__ = [
    "AuthError",
    "Authenticator",
    "AuthorizerContextAuth",
    "BearerAuth",
    "bearer_token",
]


class AuthError(Exception):
    """Authentication failed; becomes a 401 with a `WWW-Authenticate` challenge.

    `error=None` means no credentials were sent at all (RFC 6750 section 3.1:
    the challenge then carries no error code).
    """

    def __init__(self, error: str | None, description: str, status: int = 401) -> None:
        super().__init__(description)
        self.error = error
        self.description = description
        self.status = status


class Authenticator(Protocol):
    def authenticate(self, request: HttpRequest) -> Principal: ...


def bearer_token(request: HttpRequest) -> str:
    """The bearer token from the `Authorization` header, or raise `AuthError`.

    Tokens in the query string are refused by the handler before this runs
    (the MCP authorization spec forbids them).
    """
    value = request.header("authorization")
    if value is None or not value.strip():
        raise AuthError(None, "authentication required")
    scheme, _, token = value.strip().partition(" ")
    token = token.strip()
    if scheme.lower() != "bearer" or not token:
        raise AuthError("invalid_request", "expected a Bearer token")
    if any(c in token for c in " ,\t"):
        # Two Authorization headers arrive comma-joined from API Gateway.
        raise AuthError("invalid_request", "expected exactly one Bearer token")
    return token


class BearerAuth:
    """Verify the bearer token with a `JWTVerifier` on every request."""

    def __init__(self, verifier: JWTVerifier) -> None:
        self.verifier = verifier

    @property
    def audience(self) -> tuple[str, ...]:
        return self.verifier.audience

    def authenticate(self, request: HttpRequest) -> Principal:
        token = bearer_token(request)
        try:
            return self.verifier.verify(token)
        except InvalidToken as exc:
            raise AuthError("invalid_token", exc.reason) from None


def _str(value: Any) -> str:
    return value if isinstance(value, str) else ""


class AuthorizerContextAuth:
    """Read the principal an API Gateway authorizer attached to the request.

    `source="lambda"` reads `requestContext.authorizer.lambda` (the context
    returned by `authorizer_handler_for`); `source="jwt"` reads the claims of
    API Gateway's native JWT authorizer. A request without that context is
    refused (fail closed): it means a route was deployed without its
    authorizer.
    """

    def __init__(
        self,
        source: Literal["lambda", "jwt"] = "lambda",
        *,
        audience: str | tuple[str, ...] = (),
        clock: Callable[[], float] = time.time,
    ) -> None:
        if source not in ("lambda", "jwt"):
            raise ValueError("source must be 'lambda' or 'jwt'")
        self.source = source
        self.audience = (audience,) if isinstance(audience, str) else tuple(audience)
        self._clock = clock

    def authenticate(self, request: HttpRequest) -> Principal:
        ctx = request.authorizer.get(self.source)
        if not isinstance(ctx, Mapping):
            raise AuthError(None, "authentication required")
        claims: Mapping[str, Any] = ctx
        if self.source == "jwt":
            inner = ctx.get("claims")
            claims = inner if isinstance(inner, Mapping) else {}
        subject = _str(claims.get("sub"))
        if not subject:
            raise AuthError("invalid_token", "missing required claim")
        exp = claims.get("exp")
        try:
            expires_at = int(exp) if exp is not None else None
        except (TypeError, ValueError):
            raise AuthError("invalid_token", "invalid token") from None
        # A cached authorizer decision can outlive the token: re-check expiry.
        if expires_at is not None and expires_at < self._clock():
            raise AuthError("invalid_token", "token expired")
        raw_scope = claims.get("scope", claims.get("scp", ""))
        if isinstance(raw_scope, str):
            # API GW renders a JWT list claim as "[a b]".
            scopes = frozenset(raw_scope.strip("[]").split())
        elif isinstance(raw_scope, list):
            scopes = frozenset(s for s in raw_scope if isinstance(s, str))
        else:
            scopes = frozenset()
        aud = _str(claims.get("aud"))
        return Principal(
            subject=subject,
            issuer=_str(claims.get("iss")),
            client_id=_str(claims.get("client_id")) or _str(claims.get("azp")),
            scopes=scopes,
            expires_at=expires_at,
            audience=(aud,) if aud else (),
            claims=MappingProxyType(dict(claims)),
        )
