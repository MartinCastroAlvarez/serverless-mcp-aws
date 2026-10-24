"""The Lambda authorizer variant, end to end with the MCP handler."""

from __future__ import annotations

import json
import time
from typing import Any

import pytest

from serverless_mcp_aws import AuthorizerContextAuth
from serverless_mcp_aws import JWTVerifier
from serverless_mcp_aws import authorizer_handler_for
from serverless_mcp_aws import lambda_handler_for
from tests.conftest import EVENTS
from tests.conftest import METADATA
from tests.conftest import POLICY
from tests.conftest import RESOURCE
from tests.conftest import body_of
from tests.conftest import event
from tests.conftest import make_server
from tests.conftest import make_token
from tests.conftest import rpc


def auth_event(authorization: str | None) -> dict[str, Any]:
    evt: dict[str, Any] = json.loads((EVENTS / "authorizer_request.json").read_text())
    if authorization is None:
        evt["headers"].pop("authorization")
        evt["identitySource"] = []
    else:
        evt["headers"]["authorization"] = authorization
        evt["identitySource"] = [authorization]
    return evt


def test_valid_token_is_authorized_with_identity_context(verifier: JWTVerifier) -> None:
    handler = authorizer_handler_for(verifier)
    result = handler(auth_event(f"Bearer {make_token(scope='notes:read')}"), None)
    assert result["isAuthorized"] is True
    ctx = result["context"]
    assert ctx["sub"] == "alice" and ctx["scope"] == "notes:read" and ctx["aud"] == RESOURCE
    assert isinstance(ctx["exp"], int)
    # Only primitives (API Gateway's rule), and never the token.
    assert all(isinstance(v, str | int) for v in ctx.values())
    assert "Bearer" not in json.dumps(ctx)


@pytest.mark.parametrize(
    "authorization",
    [None, "Basic abc", "Bearer not-a-jwt", "Bearer a,Bearer b"],
)
def test_bad_credentials_are_refused(verifier: JWTVerifier, authorization: str | None) -> None:
    assert authorizer_handler_for(verifier)(auth_event(authorization), None) == {
        "isAuthorized": False
    }


def test_expired_and_foreign_tokens_are_refused(verifier: JWTVerifier) -> None:
    handler = authorizer_handler_for(verifier)
    assert not handler(auth_event(f"Bearer {make_token(exp=int(time.time()) - 999)}"), None)[
        "isAuthorized"
    ]
    assert not handler(auth_event(f"Bearer {make_token(aud='https://x.example.com')}"), None)[
        "isAuthorized"
    ]


def test_unexpected_errors_never_authorize(
    verifier: JWTVerifier, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(token: str) -> Any:
        raise RuntimeError("bug")

    monkeypatch.setattr(verifier, "verify", boom)
    assert authorizer_handler_for(verifier)(auth_event("Bearer x.y.z"), None) == {
        "isAuthorized": False
    }


def test_malformed_authorizer_event() -> None:
    assert authorizer_handler_for(None)({"headers": None}, None) == {"isAuthorized": False}  # type: ignore[arg-type]


def test_authorizer_context_drives_the_mcp_handler(verifier: JWTVerifier) -> None:
    decision = authorizer_handler_for(verifier)(
        auth_event(f"Bearer {make_token(scope='notes:read')}"), None
    )
    mcp = lambda_handler_for(
        make_server(),
        auth=AuthorizerContextAuth(audience=RESOURCE),
        resource_metadata=METADATA,
        tool_policy=POLICY,
    )
    headers = {"mcp-protocol-version": "2025-11-25"}
    ok = mcp(
        event(
            rpc("tools/call", {"name": "whoami", "arguments": {}}),
            headers=headers,
            authorizer={"lambda": decision["context"]},
        ),
        None,
    )
    assert ok["statusCode"] == 200
    assert body_of(ok)["result"]["structuredContent"]["sub"] == "alice"
    denied = mcp(
        event(
            rpc("tools/call", {"name": "admin_reset", "arguments": {}}),
            headers=headers,
            authorizer={"lambda": decision["context"]},
        ),
        None,
    )
    assert denied["statusCode"] == 403


def test_route_deployed_without_authorizer_fails_closed() -> None:
    mcp = lambda_handler_for(
        make_server(), auth=AuthorizerContextAuth(), resource_metadata=METADATA
    )
    # A client cannot forge requestContext: without it the request is refused.
    result = mcp(event(rpc("tools/list"), headers={"x-authorizer": '{"sub":"admin"}'}), None)
    assert result["statusCode"] == 401
