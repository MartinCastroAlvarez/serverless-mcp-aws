"""A Lambda authorizer for API Gateway HTTP APIs (payload 2.0, simple responses).

```python
# authorizer.py, deployed as its own function
from serverless_mcp_aws import JWTVerifier, authorizer_handler_for

handler = authorizer_handler_for(JWTVerifier.from_env())
```

The MCP function then uses `AuthorizerContextAuth()` and reads the principal
from `requestContext.authorizer.lambda`. The context carries identity claims
only, never the token.

Trade-off: API Gateway answers a missing token with a bare 401 and a refused
one with a bare 403, without the `WWW-Authenticate` challenge. MCP clients then
fall back to the well-known metadata URL, which this library always serves.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from collections.abc import Mapping
from typing import Any

from serverless_mcp_aws.auth.authenticators import AuthError
from serverless_mcp_aws.auth.authenticators import bearer_token
from serverless_mcp_aws.auth.jwt import InvalidToken
from serverless_mcp_aws.auth.jwt import JWTVerifier
from serverless_mcp_aws.events import HttpRequest

__all__ = ["authorizer_handler_for"]

logger = logging.getLogger(__name__)

LambdaHandler = Callable[[Mapping[str, Any], Any], dict[str, Any]]


def authorizer_handler_for(verifier: JWTVerifier) -> LambdaHandler:
    """Build `handler(event, context)` for an HTTP API REQUEST authorizer."""

    def handler(event: Mapping[str, Any], context: Any = None) -> dict[str, Any]:
        headers = event.get("headers") if isinstance(event, Mapping) else None
        if not isinstance(headers, Mapping):
            return {"isAuthorized": False}
        request = HttpRequest(
            method="",
            path="",
            headers={str(k).lower(): str(v) for k, v in headers.items()},
            body=b"",
        )
        try:
            principal = verifier.verify(bearer_token(request))
        except AuthError as exc:
            logger.info("authorizer refused a request: %s", exc.description)
            return {"isAuthorized": False}
        except InvalidToken as exc:
            logger.info("authorizer refused a request: %s", exc.reason)
            return {"isAuthorized": False}
        except Exception as exc:  # the verifier is the boundary: never fail open
            logger.warning("authorizer error: %s", type(exc).__name__)
            return {"isAuthorized": False}
        ctx: dict[str, Any] = {
            "sub": principal.subject,
            "iss": principal.issuer,
            "client_id": principal.client_id,
            "scope": " ".join(sorted(principal.scopes)),
            "aud": principal.audience[0] if principal.audience else "",
        }
        if principal.expires_at is not None:
            ctx["exp"] = principal.expires_at
        return {"isAuthorized": True, "context": ctx}

    return handler
