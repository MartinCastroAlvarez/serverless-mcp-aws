"""A tiny local HTTP server that runs the *same* Lambda handler.

Each HTTP request becomes an API Gateway HTTP API (payload 2.0) event, goes
through the handler, and the proxy response is written back. With
`authorizer=` it also emulates API Gateway's Lambda authorizer step: 401
without a token, 403 when the authorizer refuses, and the returned context in
`requestContext.authorizer.lambda` otherwise.

For local development only: it binds to 127.0.0.1 by default and is not
hardened for the open internet.
"""

from __future__ import annotations

import base64
import importlib
import json
import logging
import re
import sys
import threading
import time
import uuid
from collections.abc import Callable
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any
from typing import cast

from mcp.server.lowlevel.server import Server
from mcp.server.mcpserver import MCPServer

from serverless_mcp_aws.handler import McpLambdaHandler
from serverless_mcp_aws.handler import lambda_handler_for
from serverless_mcp_aws.origin import LOCAL_ORIGINS

__all__ = ["DevServer", "load_target", "make_event"]

logger = logging.getLogger(__name__)

LambdaFn = Callable[[Mapping[str, Any], Any], dict[str, Any]]
_TARGET = re.compile(r"^[A-Za-z_][\w.]*:[A-Za-z_]\w*$")
MAX_DEV_BODY = 6 * 1024 * 1024  # Lambda's synchronous payload limit


def load_target(spec: str, *, search_path: Path | None = None) -> Any:
    """Import `module:attribute` (from the current directory first)."""
    if not _TARGET.match(spec):
        raise ValueError(f"expected module:attribute, got {spec!r}")
    module_name, attr = spec.split(":")
    root = str((search_path or Path.cwd()).resolve())
    if root not in sys.path:
        sys.path.insert(0, root)
    module = importlib.import_module(module_name)
    try:
        return getattr(module, attr)
    except AttributeError:
        raise ValueError(f"{module_name} has no attribute {attr!r}") from None


def as_handler(target: Any) -> LambdaFn:
    """An MCP server becomes an anonymous localhost handler; a handler stays as it is."""
    if isinstance(target, MCPServer | Server):
        return lambda_handler_for(target, allow_anonymous=True, allowed_origins=LOCAL_ORIGINS)
    if isinstance(target, McpLambdaHandler) or callable(target):
        return cast(LambdaFn, target)
    raise TypeError("target must be an MCPServer, a Server or a Lambda handler")


def make_event(
    *,
    method: str,
    target: str,
    headers: list[tuple[str, str]],
    body: bytes,
    source_ip: str = "127.0.0.1",
    host: str = "localhost",
) -> dict[str, Any]:
    """An API Gateway HTTP API payload-2.0 event, as API Gateway would build it."""
    path, _, query = target.partition("?")
    merged: dict[str, str] = {}
    cookies: list[str] = []
    for name, value in headers:
        key = name.lower()
        if key == "cookie":
            cookies.extend(c.strip() for c in value.split(";") if c.strip())
            continue
        merged[key] = f"{merged[key]},{value}" if key in merged else value
    try:
        text: str | None = body.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    event: dict[str, Any] = {
        "version": "2.0",
        "routeKey": "$default",
        "rawPath": path or "/",
        "rawQueryString": query,
        "headers": merged,
        "requestContext": {
            "accountId": "000000000000",
            "apiId": "local",
            "domainName": host,
            "requestId": uuid.uuid4().hex,
            "stage": "$default",
            "timeEpoch": int(time.time() * 1000),
            "http": {
                "method": method,
                "path": path or "/",
                "protocol": "HTTP/1.1",
                "sourceIp": source_ip,
                "userAgent": merged.get("user-agent", ""),
            },
        },
        "isBase64Encoded": text is None,
    }
    if cookies:
        event["cookies"] = cookies
    if body:
        event["body"] = text if text is not None else base64.b64encode(body).decode("ascii")
    return event


def _authorizer_event(event: Mapping[str, Any]) -> dict[str, Any]:
    headers = event.get("headers", {})
    return {
        "version": "2.0",
        "type": "REQUEST",
        "routeArn": "arn:aws:execute-api:local:000000000000:local/$default/ANY/",
        "identitySource": [headers.get("authorization", "")],
        "routeKey": "$default",
        "rawPath": event.get("rawPath"),
        "rawQueryString": event.get("rawQueryString", ""),
        "headers": headers,
        "requestContext": event.get("requestContext", {}),
    }


def _authorize(authorizer: LambdaFn, event: dict[str, Any]) -> dict[str, Any] | None:
    """Emulate API Gateway's REQUEST authorizer step; a response means "stop here"."""
    method = event["requestContext"]["http"]["method"]
    if method == "OPTIONS" or str(event.get("rawPath", "")).startswith("/.well-known/"):
        return None  # the CDK construct leaves these routes public too
    if not event["headers"].get("authorization"):
        return {"statusCode": 401, "headers": {}, "body": json.dumps({"message": "Unauthorized"})}
    decision = authorizer(_authorizer_event(event), None)
    if not decision.get("isAuthorized"):
        return {"statusCode": 403, "headers": {}, "body": json.dumps({"message": "Forbidden"})}
    event["requestContext"]["authorizer"] = {"lambda": dict(decision.get("context") or {})}
    return None


class DevServer:
    """Serve a Lambda handler on `http://host:port` (port 0 picks a free one)."""

    def __init__(
        self,
        handler: LambdaFn,
        *,
        host: str = "127.0.0.1",
        port: int = 8000,
        authorizer: LambdaFn | None = None,
    ) -> None:
        self.handler = handler
        self.authorizer = authorizer
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            server_version = "serverless-mcp-aws-dev"
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:
                logger.debug(format, *args)

            def _serve(self) -> None:
                length = int(self.headers.get("content-length") or 0)
                if length > MAX_DEV_BODY:
                    self._write({"statusCode": 413, "headers": {}, "body": ""})
                    return
                body = self.rfile.read(length) if length else b""
                event = make_event(
                    method=self.command,
                    target=self.path,
                    headers=list(self.headers.items()),
                    body=body,
                    source_ip=self.client_address[0],
                    host=self.headers.get("host", "localhost"),
                )
                self._write(outer.invoke(event))

            do_GET = do_POST = do_DELETE = do_PUT = do_PATCH = do_OPTIONS = do_HEAD = _serve

            def _write(self, result: Mapping[str, Any]) -> None:
                raw = result.get("body") or ""
                payload = (
                    base64.b64decode(raw) if result.get("isBase64Encoded") else raw.encode("utf-8")
                )
                self.send_response(int(result.get("statusCode", 200)))
                for key, value in (result.get("headers") or {}).items():
                    self.send_header(key, str(value))
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(payload)

        self._httpd = ThreadingHTTPServer((host, port), _Handler)
        self._httpd.daemon_threads = True
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        host, port = self._httpd.server_address[:2]
        return f"http://{host!s}:{port}"

    def invoke(self, event: dict[str, Any]) -> dict[str, Any]:
        """Run the (emulated) authorizer, then the handler."""
        if self.authorizer is not None:
            denied = _authorize(self.authorizer, event)
            if denied is not None:
                return denied
        return self.handler(event, None)

    def serve_forever(self) -> None:
        self._httpd.serve_forever()

    def start(self) -> DevServer:
        """Serve in a background thread (for tests)."""
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        """Stop a server started with `start()`."""
        if self._thread is not None:
            self._httpd.shutdown()
            self._thread.join(timeout=5)
            self._thread = None
        self.close()

    def close(self) -> None:
        """Release the socket (after `serve_forever()` returned)."""
        self._httpd.server_close()

    def __enter__(self) -> DevServer:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()
