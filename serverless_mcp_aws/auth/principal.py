"""Who is calling: the verified identity a request runs as."""

from __future__ import annotations

import contextlib
import hashlib
from collections.abc import Iterator
from collections.abc import Mapping
from contextvars import ContextVar
from dataclasses import dataclass
from dataclasses import field
from types import MappingProxyType
from typing import Any

__all__ = ["ANONYMOUS", "Principal", "current_principal", "principal_scope"]


@dataclass(frozen=True)
class Principal:
    """A verified caller.

    Built from a validated access token (or from the context a Lambda
    authorizer returned). It never holds the raw token: tools act with the
    function's own AWS credentials on the caller's behalf, scoped by
    `subject`, and never forward the caller's token to another service.
    """

    subject: str
    issuer: str = ""
    client_id: str = ""
    scopes: frozenset[str] = frozenset()
    expires_at: int | None = None
    audience: tuple[str, ...] = ()
    claims: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))
    anonymous: bool = False

    @property
    def key(self) -> str:
        """A stable, path-safe id for per-caller storage (hash of issuer + subject)."""
        raw = f"{self.issuer}\x00{self.subject}".encode()
        return hashlib.sha256(raw).hexdigest()[:32]

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


ANONYMOUS = Principal(subject="anonymous", anonymous=True)
"""The principal of a request to a server configured with `allow_anonymous=True`."""

_current: ContextVar[Principal | None] = ContextVar("serverless_mcp_aws_principal", default=None)


def current_principal() -> Principal:
    """The principal of the MCP request being handled.

    Call it from a tool. Raises `LookupError` outside a request handled by
    this library, so a tool can never silently run as "nobody".
    """
    principal = _current.get()
    if principal is None:
        raise LookupError("current_principal() called outside an MCP request")
    return principal


@contextlib.contextmanager
def principal_scope(principal: Principal) -> Iterator[None]:
    """Run a block as `principal` (used by the handler; handy in tests)."""
    token = _current.set(principal)
    try:
        yield
    finally:
        _current.reset(token)
