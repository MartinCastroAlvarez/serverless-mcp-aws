"""JSON-RPC 2.0 helpers: error envelopes and message classification."""

from __future__ import annotations

from typing import Any
from typing import Final

__all__ = [
    "FORBIDDEN",
    "INTERNAL_ERROR",
    "INVALID_REQUEST",
    "METHOD_NOT_FOUND",
    "PARSE_ERROR",
    "UNAUTHORIZED",
    "error",
    "is_notification",
    "is_request",
    "request_id",
]

PARSE_ERROR: Final = -32700
INVALID_REQUEST: Final = -32600
METHOD_NOT_FOUND: Final = -32601
INTERNAL_ERROR: Final = -32603
# Implementation-defined server errors (-32000..-32099). MCP reserves -32020
# and up for protocol errors, so stay well below.
UNAUTHORIZED: Final = -32001
FORBIDDEN: Final = -32003


def error(code: int, message: str, msg_id: Any = None) -> dict[str, Any]:
    """A JSON-RPC error response. `msg_id=None` gives the spec's id-less form."""
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def is_request(msg: Any) -> bool:
    return isinstance(msg, dict) and isinstance(msg.get("method"), str) and "id" in msg


def is_notification(msg: Any) -> bool:
    return isinstance(msg, dict) and isinstance(msg.get("method"), str) and "id" not in msg


def request_id(msg: Any) -> Any:
    """The id of a request, or None. Only string and integer ids are echoed."""
    if isinstance(msg, dict):
        value = msg.get("id")
        if isinstance(value, str | int) and not isinstance(value, bool):
            return value
    return None
