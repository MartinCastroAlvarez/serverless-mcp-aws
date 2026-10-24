"""The Lambda handler: API Gateway HTTP API event -> MCP -> Lambda proxy response.

Order of checks for the MCP endpoint (each one can end the request):

1. routing (the MCP path, the protected-resource-metadata paths, else 404)
2. CORS preflight (`OPTIONS`)
3. `Origin` allowlist -> 403 (DNS rebinding / cross-site requests)
4. method -> 405 (`GET`/`DELETE` belong to session-based servers; this one is stateless)
5. a token in the query string -> 400 (forbidden by the MCP authorization spec)
6. body size -> 413
7. authentication -> 401 with a `WWW-Authenticate` challenge
8. JSON parsing, JSON-RPC batch handling (2025-03-26 only)
9. per-tool authorization -> 403 `insufficient_scope`
10. the official MCP SDK handles the message; `tools/list` is filtered to the
    tools the caller may use
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from collections.abc import Iterable
from collections.abc import Mapping
from typing import Any
from typing import Final

from mcp.server.lowlevel.server import Server
from mcp.server.mcpserver import MCPServer

from serverless_mcp_aws import jsonrpc
from serverless_mcp_aws.auth.authenticators import Authenticator
from serverless_mcp_aws.auth.authenticators import AuthError
from serverless_mcp_aws.auth.metadata import ProtectedResourceMetadata
from serverless_mcp_aws.auth.metadata import challenge
from serverless_mcp_aws.auth.policy import ToolPolicy
from serverless_mcp_aws.auth.principal import ANONYMOUS
from serverless_mcp_aws.auth.principal import Principal
from serverless_mcp_aws.bridge import Exchange
from serverless_mcp_aws.bridge import SdkBridge
from serverless_mcp_aws.events import BadEvent
from serverless_mcp_aws.events import BodyTooLarge
from serverless_mcp_aws.events import HttpRequest
from serverless_mcp_aws.events import HttpResponse
from serverless_mcp_aws.events import json_response
from serverless_mcp_aws.origin import OriginPolicy

__all__ = ["McpLambdaHandler", "lambda_handler_for"]

logger = logging.getLogger(__name__)

BATCH_PROTOCOL_VERSION: Final = "2025-03-26"
"""The only protocol revision that allowed JSON-RPC batches (removed in 2025-06-18)."""

DEFAULT_MAX_BODY_BYTES: Final = 1024 * 1024
DEFAULT_MAX_BATCH: Final = 20
_LOGGABLE_METHOD = re.compile(r"^[A-Za-z][A-Za-z0-9_/]{0,63}$")
_HEADER_TOKEN = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
_BASE_HEADERS: Final = {"cache-control": "no-store", "x-content-type-options": "nosniff"}
_UNSERVABLE_METHODS: Final = frozenset({"subscriptions/listen"})
_TOKEN_QUERY_PARAMS: Final = frozenset({"access_token", "token", "id_token"})


class McpLambdaHandler:
    """A callable Lambda handler serving one MCP server over stateless Streamable HTTP.

    Build it once at module scope (cold start) and export it:

    ```python
    handler = lambda_handler_for(server, auth=BearerAuth(JWTVerifier.from_env()),
                                 resource_metadata=ProtectedResourceMetadata.from_env())
    ```
    """

    def __init__(
        self,
        server: MCPServer | Server[Any],
        *,
        auth: Authenticator | None = None,
        allow_anonymous: bool = False,
        resource_metadata: ProtectedResourceMetadata | None = None,
        tool_policy: ToolPolicy | None = None,
        allowed_origins: Iterable[str] = (),
        mcp_path: str = "/mcp",
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
        max_batch_size: int = DEFAULT_MAX_BATCH,
    ) -> None:
        if auth is None and not allow_anonymous:
            raise ValueError(
                "no authentication configured: pass auth=BearerAuth(...) (or "
                "AuthorizerContextAuth()), or allow_anonymous=True for a public server"
            )
        if auth is not None and allow_anonymous:
            raise ValueError("auth and allow_anonymous=True are mutually exclusive")
        if auth is not None and resource_metadata is None:
            raise ValueError(
                "an authenticated MCP server must publish protected resource metadata "
                "(resource_metadata=ProtectedResourceMetadata(...))"
            )
        if tool_policy is not None and auth is None:
            raise ValueError("a tool_policy needs authenticated callers (auth=...)")
        audience = tuple(getattr(auth, "audience", ()) or ())
        if (
            resource_metadata is not None
            and audience
            and resource_metadata.resource not in audience
        ):
            raise ValueError(
                "the token audience must include the resource URI "
                f"{resource_metadata.resource!r} (RFC 8707): tokens for other services "
                "must not be accepted"
            )
        if not mcp_path.startswith("/") or mcp_path != mcp_path.rstrip("/") or "/." in mcp_path:
            raise ValueError("mcp_path must look like /mcp")
        if max_body_bytes <= 0 or max_batch_size <= 0:
            raise ValueError("limits must be positive")
        self.bridge = SdkBridge(server, max_body_bytes=max_body_bytes)
        self.auth = auth
        self.resource_metadata = resource_metadata
        self.tool_policy = tool_policy
        self.origins = OriginPolicy.of(allowed_origins)
        self.mcp_path = mcp_path
        self.max_body_bytes = max_body_bytes
        self.max_batch_size = max_batch_size
        self._metadata_paths = resource_metadata.paths() if resource_metadata else ()

    # ------------------------------------------------------------------ #
    # Entry points
    # ------------------------------------------------------------------ #
    def __call__(self, event: Mapping[str, Any], context: Any = None) -> dict[str, Any]:
        """The synchronous Lambda entry point."""
        return asyncio.run(self.handle(event))

    async def handle(self, event: Mapping[str, Any]) -> dict[str, Any]:
        """Async entry point (use it when an event loop is already running)."""
        started = time.monotonic()
        try:
            request = HttpRequest.from_event(event, max_body_bytes=self.max_body_bytes)
        except BodyTooLarge:
            return self._finish(
                json_response(413, jsonrpc.error(jsonrpc.INVALID_REQUEST, "Request body too large"))
            ).to_lambda()
        except BadEvent:
            return self._finish(
                json_response(400, jsonrpc.error(jsonrpc.INVALID_REQUEST, "Bad request"))
            ).to_lambda()
        rpc_method = "-"
        try:
            response, rpc_method = await self.handle_request(request)
        except Exception as exc:
            # Never leak internals to the caller; log the type, not the payload.
            logger.error("unhandled error: %s", type(exc).__name__, exc_info=True)
            response = json_response(500, jsonrpc.error(jsonrpc.INTERNAL_ERROR, "Internal error"))
        response = self._finish(response, request)
        logger.info(
            "mcp %s %s -> %d (%.0f ms)",
            request.method,
            rpc_method,
            response.status,
            (time.monotonic() - started) * 1000,
        )
        return response.to_lambda()

    async def handle_request(self, request: HttpRequest) -> tuple[HttpResponse, str]:
        path = request.path.rstrip("/") or "/"
        if self.resource_metadata is not None and path in self._metadata_paths:
            return self._metadata(request, self.resource_metadata), "-"
        if path != self.mcp_path:
            return json_response(404, {"error": "not_found"}), "-"

        origin = request.header("origin")
        if request.method == "OPTIONS":
            return self._preflight(request, origin), "-"
        if not self.origins.allows(origin):
            return json_response(
                403, jsonrpc.error(jsonrpc.FORBIDDEN, "Forbidden: origin not allowed")
            ), "-"
        if request.method != "POST":
            return json_response(
                405,
                jsonrpc.error(
                    jsonrpc.INVALID_REQUEST, "Method not allowed: this server is stateless"
                ),
                {"allow": "POST, OPTIONS"},
            ), "-"
        if _TOKEN_QUERY_PARAMS & set(request.query):
            return json_response(
                400,
                jsonrpc.error(jsonrpc.INVALID_REQUEST, "Access tokens are not accepted in the URL"),
            ), "-"

        try:
            principal = self._authenticate(request)
        except AuthError as exc:
            return self._unauthorized(exc), "-"

        try:
            payload = json.loads(request.body)
        except (ValueError, UnicodeDecodeError):
            return json_response(400, jsonrpc.error(jsonrpc.PARSE_ERROR, "Parse error")), "-"

        if isinstance(payload, list):
            return await self._batch(request, payload, principal), "batch"
        method = payload.get("method") if isinstance(payload, dict) else None
        label = method if isinstance(method, str) and _LOGGABLE_METHOD.match(method) else "-"
        async with self.bridge.open() as exchange:
            return await self._single(request, payload, request.body, principal, exchange), label

    # ------------------------------------------------------------------ #
    # Steps
    # ------------------------------------------------------------------ #
    def _authenticate(self, request: HttpRequest) -> Principal:
        if self.auth is None:
            return ANONYMOUS
        return self.auth.authenticate(request)

    def _unauthorized(self, exc: AuthError) -> HttpResponse:
        header = challenge(
            resource_metadata=self.resource_metadata.metadata_url
            if self.resource_metadata
            else None,
            error=exc.error,
            description=exc.description if exc.error else None,
            scopes=self.resource_metadata.scopes_supported if self.resource_metadata else (),
        )
        return json_response(
            exc.status,
            jsonrpc.error(jsonrpc.UNAUTHORIZED, f"Unauthorized: {exc.description}"),
            {"www-authenticate": header},
        )

    def _forbidden_tool(self, tool: str, msg_id: Any) -> HttpResponse:
        scopes = self.tool_policy.scopes_for(tool) if self.tool_policy else ()
        header = challenge(
            resource_metadata=self.resource_metadata.metadata_url
            if self.resource_metadata
            else None,
            error="insufficient_scope",
            description="The token does not grant this tool",
            scopes=scopes,
        )
        return json_response(
            403,
            jsonrpc.error(jsonrpc.FORBIDDEN, "Forbidden: insufficient scope for this tool", msg_id),
            {"www-authenticate": header},
        )

    def _denied_tool(self, message: Any, principal: Principal) -> str | None:
        """The tool name when `message` is a tools/call the principal may not make."""
        if self.tool_policy is None or not isinstance(message, dict):
            return None
        if message.get("method") != "tools/call":
            return None
        params = message.get("params")
        name = params.get("name") if isinstance(params, dict) else None
        if not isinstance(name, str):
            return None  # malformed: the SDK rejects it
        return None if self.tool_policy.allows(principal, name) else name

    async def _single(
        self,
        request: HttpRequest,
        message: Any,
        raw: bytes,
        principal: Principal,
        exchange: Exchange,
    ) -> HttpResponse:
        method = message.get("method") if isinstance(message, dict) else None
        if method in _UNSERVABLE_METHODS:
            return json_response(
                404,
                jsonrpc.error(
                    jsonrpc.METHOD_NOT_FOUND,
                    "Method not found: long-lived streams are not available on AWS Lambda",
                    jsonrpc.request_id(message),
                ),
            )
        denied = self._denied_tool(message, principal)
        if denied is not None:
            return self._forbidden_tool(denied, jsonrpc.request_id(message))
        sdk = await exchange.post(request.headers, raw, principal)
        out_headers = {
            k: v for k, v in sdk.headers.items() if k in ("content-type", "mcp-protocol-version")
        }
        out_body = sdk.body
        if method == "tools/list" and sdk.status == 200 and self.tool_policy is not None:
            out_body = _filter_tool_list(out_body, self.tool_policy.allowed_tools(principal))
        return HttpResponse(status=sdk.status, headers=out_headers, body=out_body)

    async def _batch(
        self, request: HttpRequest, messages: list[Any], principal: Principal
    ) -> HttpResponse:
        version = request.header("mcp-protocol-version")
        if version is not None and version != BATCH_PROTOCOL_VERSION:
            return json_response(
                400,
                jsonrpc.error(
                    jsonrpc.INVALID_REQUEST,
                    "JSON-RPC batches are only supported by protocol version "
                    f"{BATCH_PROTOCOL_VERSION}",
                ),
            )
        if not messages:
            return json_response(400, jsonrpc.error(jsonrpc.INVALID_REQUEST, "Empty batch"))
        if len(messages) > self.max_batch_size:
            return json_response(
                400,
                jsonrpc.error(
                    jsonrpc.INVALID_REQUEST, f"Batch too large (max {self.max_batch_size})"
                ),
            )
        replies: list[Any] = []
        async with self.bridge.open() as exchange:
            for message in messages:
                if not isinstance(message, dict):
                    replies.append(jsonrpc.error(jsonrpc.INVALID_REQUEST, "Invalid Request"))
                    continue
                if "method" not in message:
                    continue  # a client response: nothing to answer on a stateless server
                if message.get("method") == "initialize":
                    replies.append(
                        jsonrpc.error(
                            jsonrpc.INVALID_REQUEST,
                            "initialize must not be part of a batch",
                            jsonrpc.request_id(message),
                        )
                    )
                    continue
                if self._denied_tool(message, principal) is not None:
                    replies.append(
                        jsonrpc.error(
                            jsonrpc.FORBIDDEN,
                            "Forbidden: insufficient scope for this tool",
                            jsonrpc.request_id(message),
                        )
                    )
                    continue
                raw = json.dumps(message, separators=(",", ":")).encode()
                item = await self._single(request, message, raw, principal, exchange)
                if jsonrpc.is_notification(message) or not item.body:
                    continue
                try:
                    replies.append(json.loads(item.body))
                except ValueError:
                    replies.append(
                        jsonrpc.error(
                            jsonrpc.INTERNAL_ERROR, "Internal error", jsonrpc.request_id(message)
                        )
                    )
        if not replies:
            return HttpResponse(status=202)
        return json_response(200, replies)

    def _metadata(self, request: HttpRequest, metadata: ProtectedResourceMetadata) -> HttpResponse:
        if request.method == "OPTIONS":
            return HttpResponse(
                status=204,
                headers={
                    "access-control-allow-origin": "*",
                    "access-control-allow-methods": "GET, OPTIONS",
                    "access-control-max-age": "600",
                },
            )
        if request.method not in ("GET", "HEAD"):
            return json_response(405, {"error": "method_not_allowed"}, {"allow": "GET, OPTIONS"})
        response = json_response(
            200,
            metadata.to_dict(),
            {
                # A public, non-credentialed document: any web client may read it.
                "access-control-allow-origin": "*",
                "cache-control": "public, max-age=300",
            },
        )
        if request.method == "HEAD":
            response.body = b""
        return response

    def _preflight(self, request: HttpRequest, origin: str | None) -> HttpResponse:
        if origin is None or not self.origins.allows(origin):
            return HttpResponse(status=403)
        requested = request.header("access-control-request-headers") or ""
        names = [h.strip().lower() for h in requested.split(",") if h.strip()]
        if not all(_HEADER_TOKEN.match(h) for h in names):
            return HttpResponse(status=400)
        allow = sorted(
            set(names)
            | {
                "authorization",
                "content-type",
                "accept",
                "mcp-protocol-version",
                "mcp-method",
                "mcp-name",
            }
        )
        return HttpResponse(
            status=204,
            headers={
                "access-control-allow-origin": origin,
                "access-control-allow-methods": "POST, OPTIONS",
                "access-control-allow-headers": ", ".join(allow),
                "access-control-max-age": "600",
                "vary": "Origin",
            },
        )

    def _finish(self, response: HttpResponse, request: HttpRequest | None = None) -> HttpResponse:
        headers = dict(_BASE_HEADERS)
        headers.update(response.headers)
        headers.pop("mcp-session-id", None)  # stateless: never mint or echo a session
        origin = request.header("origin") if request is not None else None
        if (
            origin is not None
            and "access-control-allow-origin" not in headers
            and self.origins.allows(origin)
        ):
            headers["access-control-allow-origin"] = origin
            headers["access-control-expose-headers"] = "WWW-Authenticate, MCP-Protocol-Version"
            headers["vary"] = "Origin"
        response.headers = headers
        return response


def _filter_tool_list(body: bytes, allowed: frozenset[str] | None) -> bytes:
    """Drop the tools the caller may not use from a `tools/list` result."""
    try:
        doc = json.loads(body)
    except ValueError:
        return body
    result = doc.get("result") if isinstance(doc, dict) else None
    if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
        return body
    if allowed is not None:
        result["tools"] = [
            t for t in result["tools"] if isinstance(t, dict) and t.get("name") in allowed
        ]
    if "cacheScope" in result:
        # The list now depends on the caller: never let a client share it.
        result["cacheScope"] = "private"
    return json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode()


def lambda_handler_for(server: MCPServer | Server[Any], **options: Any) -> McpLambdaHandler:
    """Build the Lambda handler for `server`. Options: see `McpLambdaHandler`."""
    return McpLambdaHandler(server, **options)
