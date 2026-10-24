"""Run one HTTP exchange through the MCP SDK's stateless Streamable HTTP app.

The protocol itself (initialize vs. the 2026-07-28 per-request envelope,
`MCP-Protocol-Version` / `Mcp-Method` / `Mcp-Name` header validation, Accept
checks, JSON-RPC dispatch, tool calls) is the official `mcp` SDK's. This module
only feeds it an ASGI request built from the API Gateway event and collects
the response, in stateless JSON-response mode: no sessions, no SSE streams,
nothing kept between invocations.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import AsyncIterator
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from mcp.server.auth.middleware.auth_context import AuthContextMiddleware
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from mcp.server.lowlevel.server import Server
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.types import ASGIApp
from starlette.types import Message

from serverless_mcp_aws.auth.principal import Principal
from serverless_mcp_aws.auth.principal import principal_scope

__all__ = ["Exchange", "SdkBridge", "SdkResponse"]

_INTERNAL_PATH = "/mcp"
# Never handed to tool code: the caller's credentials stay in this layer.
_WITHHELD = ""  # what tools get instead of the caller's bearer token
_STRIPPED_HEADERS = frozenset({"authorization", "cookie", "mcp-session-id", "last-event-id"})


@dataclass
class SdkResponse:
    status: int
    headers: dict[str, str]
    body: bytes


def _access_token(principal: Principal) -> AccessToken:
    # `token` is deliberately empty: tools see who is calling, never the
    # bearer token itself, so they cannot pass it through to other services.
    return AccessToken(
        token=_WITHHELD,
        client_id=principal.client_id or principal.subject,
        scopes=sorted(principal.scopes),
        expires_at=principal.expires_at,
        resource=principal.audience[0] if principal.audience else None,
        subject=principal.subject,
        claims={"iss": principal.issuer} if principal.issuer else None,
    )


class Exchange:
    """A running SDK app (lifespan entered) that serves POSTs."""

    def __init__(self, app: ASGIApp) -> None:
        self._app = app

    async def post(
        self, headers: Mapping[str, str], body: bytes, principal: Principal
    ) -> SdkResponse:
        raw_headers = [
            (k.encode("latin-1"), v.encode("latin-1"))
            for k, v in headers.items()
            if k not in _STRIPPED_HEADERS and k != "content-length"
        ]
        raw_headers.append((b"content-length", str(len(body)).encode()))
        scope: dict[str, Any] = {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.4"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "path": _INTERNAL_PATH,
            "raw_path": _INTERNAL_PATH.encode(),
            "root_path": "",
            "query_string": b"",
            "headers": raw_headers,
            "client": None,
            "server": ("lambda", 443),
        }
        if not principal.anonymous:
            scope["user"] = AuthenticatedUser(_access_token(principal))

        delivered = False

        async def receive() -> Message:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            # The client never disconnects mid-request on Lambda: wait until
            # the SDK finishes (it cancels this wait).
            await asyncio.Event().wait()
            return {"type": "http.disconnect"}  # pragma: no cover

        status = 500
        out_headers: dict[str, str] = {}
        chunks: list[bytes] = []

        async def send(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])
                for key, value in message.get("headers", []):
                    out_headers[key.decode("latin-1").lower()] = value.decode("latin-1")
            elif message["type"] == "http.response.body":
                chunks.append(message.get("body", b""))

        with principal_scope(principal):
            await self._app(scope, receive, send)
        return SdkResponse(status=status, headers=out_headers, body=b"".join(chunks))


class SdkBridge:
    """Wraps an `MCPServer` (or low-level `Server`) for per-invocation serving."""

    def __init__(self, server: MCPServer | Server[Any], *, max_body_bytes: int) -> None:
        if isinstance(server, MCPServer):
            if server.settings.auth is not None:
                raise ValueError(
                    "configure authentication on the handler (auth=...), not on the MCPServer"
                )
        elif not isinstance(server, Server):
            raise TypeError("server must be an mcp MCPServer or a low-level mcp Server")
        self.server = server
        self.max_body_bytes = max_body_bytes

    @contextlib.asynccontextmanager
    async def open(self) -> AsyncIterator[Exchange]:
        """Build a fresh stateless app and enter its lifespan for one invocation."""
        app = self.server.streamable_http_app(
            streamable_http_path=_INTERNAL_PATH,
            json_response=True,
            stateless_http=True,
            max_request_body_size=self.max_body_bytes,
            # Origin and Host are validated by the handler, against the
            # configured allowlist; API Gateway decides the Host.
            transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        )
        async with app.router.lifespan_context(app):
            yield Exchange(AuthContextMiddleware(app))
