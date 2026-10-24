"""Lambda authorizer for the notes example (`NOTES_AUTH=authorizer`)."""

from __future__ import annotations

from typing import Any

from serverless_mcp_aws import JWTVerifier
from serverless_mcp_aws import authorizer_handler_for

_handler: Any = None


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    global _handler
    if _handler is None:
        _handler = authorizer_handler_for(JWTVerifier.from_env())
    result: dict[str, Any] = _handler(event, context)
    return result
