"""The Lambda adapter, driven with API Gateway HTTP API v2.0 events."""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

import pytest
from mcp.server.lowlevel.server import Server

from serverless_mcp_aws import BearerAuth
from serverless_mcp_aws import JWTVerifier
from serverless_mcp_aws import McpLambdaHandler
from serverless_mcp_aws import ProtectedResourceMetadata
from serverless_mcp_aws import lambda_handler_for
from tests.conftest import ISSUER
from tests.conftest import JWKS_URL
from tests.conftest import LEGACY
from tests.conftest import METADATA
from tests.conftest import MODERN
from tests.conftest import MODERN_META
from tests.conftest import POLICY
from tests.conftest import RESOURCE
from tests.conftest import body_of
from tests.conftest import event
from tests.conftest import initialize
from tests.conftest import make_server
from tests.conftest import make_token
from tests.conftest import rpc

V = {"mcp-protocol-version": LEGACY}


@pytest.fixture
def anon() -> McpLambdaHandler:
    return lambda_handler_for(make_server(), allow_anonymous=True)


@pytest.fixture
def secured(verifier: JWTVerifier) -> McpLambdaHandler:
    return lambda_handler_for(
        make_server(),
        auth=BearerAuth(verifier),
        resource_metadata=METADATA,
        tool_policy=POLICY,
        allowed_origins=["https://app.example.com"],
    )


def call(handler: McpLambdaHandler, evt: dict[str, Any]) -> tuple[int, dict[str, str], Any]:
    result = handler(evt, None)
    return result["statusCode"], result["headers"], body_of(result)


def tool_call(name: str, args: dict[str, Any] | None = None, msg_id: int = 1) -> dict[str, Any]:
    return rpc("tools/call", {"name": name, "arguments": args or {}}, msg_id)


# --------------------------------------------------------------------------- #
# Protocol, through the SDK
# --------------------------------------------------------------------------- #
def test_initialize_from_the_captured_event(anon: McpLambdaHandler) -> None:
    from tests.conftest import EVENTS

    evt = json.loads((EVENTS / "post_mcp.json").read_text())
    status, headers, body = call(anon, evt)
    assert status == 200
    assert body["result"]["serverInfo"]["name"] == "demo"
    assert body["result"]["protocolVersion"] == LEGACY
    assert headers["content-type"] == "application/json"
    assert headers["cache-control"] == "no-store"
    assert "mcp-session-id" not in headers


def test_tools_call_legacy(anon: McpLambdaHandler) -> None:
    status, _, body = call(anon, event(tool_call("echo", {"text": "hi"}), headers=V))
    assert status == 200
    assert body["result"]["content"][0]["text"] == "hi"


def test_anonymous_principal_reaches_tools(anon: McpLambdaHandler) -> None:
    _, _, body = call(anon, event(tool_call("whoami"), headers=V))
    assert body["result"]["structuredContent"] == {
        "sub": "anonymous",
        "scopes": [],
        "anonymous": True,
    }


def test_modern_protocol_request(anon: McpLambdaHandler) -> None:
    msg = rpc("tools/call", {"name": "echo", "arguments": {"text": "x"}, "_meta": MODERN_META})
    headers = {"mcp-protocol-version": MODERN, "mcp-method": "tools/call", "mcp-name": "echo"}
    status, _, body = call(anon, event(msg, headers=headers))
    assert status == 200
    assert body["result"]["content"][0]["text"] == "x"


def test_modern_header_mismatch_is_rejected_by_the_sdk(anon: McpLambdaHandler) -> None:
    msg = rpc("tools/call", {"name": "echo", "arguments": {"text": "x"}, "_meta": MODERN_META})
    headers = {"mcp-protocol-version": MODERN, "mcp-method": "tools/call", "mcp-name": "other"}
    status, _, body = call(anon, event(msg, headers=headers))
    assert status == 400
    assert body["error"]["code"] == -32020  # HeaderMismatch


def test_server_discover(anon: McpLambdaHandler) -> None:
    headers = {"mcp-protocol-version": MODERN, "mcp-method": "server/discover"}
    status, _, body = call(
        anon, event(rpc("server/discover", {"_meta": MODERN_META}), headers=headers)
    )
    assert status == 200
    assert MODERN in body["result"]["supportedVersions"]


def test_unsupported_protocol_version(anon: McpLambdaHandler) -> None:
    status, _, _ = call(
        anon, event(tool_call("echo"), headers={"mcp-protocol-version": "1999-01-01"})
    )
    assert status == 400


def test_notification_is_accepted_with_202(anon: McpLambdaHandler) -> None:
    status, _, body = call(anon, event(rpc("notifications/initialized", msg_id=None), headers=V))
    assert status == 202
    assert body is None


def test_session_id_is_ignored_and_never_minted(anon: McpLambdaHandler) -> None:
    status, headers, body = call(
        anon, event(tool_call("echo", {"text": "s"}), headers={**V, "mcp-session-id": "abc"})
    )
    assert status == 200
    assert body["result"]["content"][0]["text"] == "s"
    assert "mcp-session-id" not in headers


def test_subscriptions_listen_is_refused_with_404(anon: McpLambdaHandler) -> None:
    headers = {"mcp-protocol-version": MODERN, "mcp-method": "subscriptions/listen"}
    status, _, body = call(
        anon, event(rpc("subscriptions/listen", {"_meta": MODERN_META}), headers=headers)
    )
    assert status == 404
    assert body["error"]["code"] == -32601


def test_unknown_tool_is_an_mcp_error(anon: McpLambdaHandler) -> None:
    status, _, body = call(anon, event(tool_call("nope"), headers=V))
    assert status == 200
    assert body["result"]["isError"] is True or "error" in body


def test_base64_body(anon: McpLambdaHandler) -> None:
    status, _, body = call(
        anon, event(tool_call("echo", {"text": "b64"}), headers=V, base64_body=True)
    )
    assert status == 200
    assert body["result"]["content"][0]["text"] == "b64"


def test_low_level_server_is_supported() -> None:
    handler = lambda_handler_for(Server("low"), allow_anonymous=True)
    status, _, body = call(handler, event(initialize()))
    assert status == 200
    assert body["result"]["serverInfo"]["name"] == "low"


def test_async_entry_point(anon: McpLambdaHandler) -> None:
    result = asyncio.run(anon.handle(event(tool_call("echo", {"text": "a"}), headers=V)))
    assert result["statusCode"] == 200


# --------------------------------------------------------------------------- #
# Batching
# --------------------------------------------------------------------------- #
BATCH_V = {"mcp-protocol-version": "2025-03-26"}


def test_batch_on_2025_03_26(anon: McpLambdaHandler) -> None:
    batch = [
        tool_call("echo", {"text": "one"}, 1),
        rpc("notifications/initialized", msg_id=None),
        tool_call("echo", {"text": "two"}, 2),
        {"jsonrpc": "2.0", "id": 9, "result": {}},  # a client response: nothing to say
    ]
    status, _, body = call(anon, event(batch, headers=BATCH_V))
    assert status == 200
    assert [r["id"] for r in body] == [1, 2]
    assert [r["result"]["content"][0]["text"] for r in body] == ["one", "two"]


def test_batch_without_version_header_is_2025_03_26(anon: McpLambdaHandler) -> None:
    status, _, body = call(anon, event([tool_call("echo", {"text": "x"})]))
    assert status == 200
    assert body[0]["id"] == 1


def test_batch_of_notifications_only_is_202(anon: McpLambdaHandler) -> None:
    status, _, body = call(
        anon, event([rpc("notifications/initialized", msg_id=None)], headers=BATCH_V)
    )
    assert status == 202
    assert body is None


@pytest.mark.parametrize("version", [LEGACY, "2025-06-18", MODERN])
def test_batch_refused_on_later_versions(anon: McpLambdaHandler, version: str) -> None:
    status, _, body = call(
        anon, event([tool_call("echo")], headers={"mcp-protocol-version": version})
    )
    assert status == 400
    assert body["error"]["code"] == -32600
    assert "2025-03-26" in body["error"]["message"]


def test_empty_and_oversized_batches(anon: McpLambdaHandler) -> None:
    assert call(anon, event([], headers=BATCH_V))[0] == 400
    big = [tool_call("echo", {"text": "x"}, i) for i in range(21)]
    status, _, body = call(anon, event(big, headers=BATCH_V))
    assert status == 400
    assert "too large" in body["error"]["message"]


def test_batch_with_invalid_items_and_initialize(anon: McpLambdaHandler) -> None:
    status, _, body = call(anon, event([3, initialize()], headers=BATCH_V))
    assert status == 200
    assert body[0]["error"]["code"] == -32600 and body[0]["id"] is None
    assert body[1]["id"] == 1 and "batch" in body[1]["error"]["message"]


def test_batch_respects_tool_policy(secured: McpLambdaHandler) -> None:
    token = make_token(scope="notes:read")
    batch = [tool_call("echo", {"text": "ok"}, 1), tool_call("admin_reset", {}, 2)]
    status, _, body = call(secured, event(batch, headers=BATCH_V, token=token))
    assert status == 200
    assert body[0]["result"]["content"][0]["text"] == "ok"
    assert body[1]["error"]["code"] == -32003


# --------------------------------------------------------------------------- #
# HTTP-level checks
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("method", ["GET", "DELETE", "PUT"])
def test_non_post_methods_get_405(anon: McpLambdaHandler, method: str) -> None:
    status, headers, _ = call(anon, event(method=method))
    assert status == 405
    assert headers["allow"] == "POST, OPTIONS"


def test_unknown_path_is_404(anon: McpLambdaHandler) -> None:
    assert call(anon, event(tool_call("echo"), path="/other"))[0] == 404


def test_trailing_slash_is_the_same_endpoint(anon: McpLambdaHandler) -> None:
    assert call(anon, event(tool_call("echo", {"text": "x"}), path="/mcp/", headers=V))[0] == 200


def test_invalid_json_is_a_parse_error(anon: McpLambdaHandler) -> None:
    status, _, body = call(anon, event(raw_body="{not json", headers=V))
    assert status == 400
    assert body["error"]["code"] == -32700


def test_body_too_large(verifier: JWTVerifier) -> None:
    handler = lambda_handler_for(make_server(), allow_anonymous=True, max_body_bytes=100)
    status, _, _ = call(handler, event(tool_call("echo", {"text": "x" * 200}), headers=V))
    assert status == 413
    status, _, _ = call(
        handler, event(tool_call("echo", {"text": "x" * 200}), headers=V, base64_body=True)
    )
    assert status == 413


@pytest.mark.parametrize(
    "bad",
    [
        {},
        {"version": "1.0"},
        {"version": "2.0"},
        {"version": "2.0", "requestContext": {}},
        {"version": "2.0", "requestContext": {"http": {}}},
        {
            "version": "2.0",
            "rawPath": "/mcp",
            "requestContext": {"http": {"method": "POST"}},
            "headers": [],
        },
        {
            "version": "2.0",
            "rawPath": "/mcp",
            "requestContext": {"http": {"method": "POST"}},
            "headers": {"a": 1},
        },
        {
            "version": "2.0",
            "rawPath": "/mcp",
            "requestContext": {"http": {"method": "POST"}},
            "body": 3,
        },
        {
            "version": "2.0",
            "rawPath": "/mcp",
            "requestContext": {"http": {"method": "POST"}},
            "body": "***",
            "isBase64Encoded": True,
        },
    ],
)
def test_malformed_events_are_400(anon: McpLambdaHandler, bad: dict[str, Any]) -> None:
    assert anon(bad, None)["statusCode"] == 400


def test_internal_errors_do_not_leak(
    anon: McpLambdaHandler, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    async def boom(*a: Any, **k: Any) -> Any:
        raise RuntimeError("secret detail /etc/passwd")

    monkeypatch.setattr(anon, "handle_request", boom)
    with caplog.at_level(logging.ERROR):
        status, _, body = call(anon, event(tool_call("echo"), headers=V))
    assert status == 500
    assert body["error"] == {"code": -32603, "message": "Internal error"}
    assert "secret detail" not in json.dumps(body)


# --------------------------------------------------------------------------- #
# Origin / CORS
# --------------------------------------------------------------------------- #
def test_foreign_origin_is_403(secured: McpLambdaHandler) -> None:
    status, headers, body = call(
        secured,
        event(initialize(), headers={"origin": "https://evil.example.com"}, token=make_token()),
    )
    assert status == 403
    assert body["id"] is None
    assert "access-control-allow-origin" not in headers


def test_null_origin_is_403(secured: McpLambdaHandler) -> None:
    assert (
        call(secured, event(initialize(), headers={"origin": "null"}, token=make_token()))[0] == 403
    )


def test_origin_check_runs_before_auth(secured: McpLambdaHandler) -> None:
    # A rebinding page gets 403 even without a token: nothing to probe.
    assert call(secured, event(initialize(), headers={"origin": "http://localhost:1"}))[0] == 403


def test_allowed_origin_gets_cors_headers(secured: McpLambdaHandler) -> None:
    status, headers, _ = call(
        secured,
        event(initialize(), headers={"origin": "https://app.example.com"}, token=make_token()),
    )
    assert status == 200
    assert headers["access-control-allow-origin"] == "https://app.example.com"
    assert "WWW-Authenticate" in headers["access-control-expose-headers"]
    assert headers["vary"] == "Origin"


def test_anonymous_server_refuses_every_browser_origin(anon: McpLambdaHandler) -> None:
    assert call(anon, event(initialize(), headers={"origin": "https://app.example.com"}))[0] == 403


def test_preflight(secured: McpLambdaHandler) -> None:
    evt = event(
        method="OPTIONS",
        headers={
            "origin": "https://app.example.com",
            "access-control-request-method": "POST",
            "access-control-request-headers": "authorization, content-type, mcp-param-region",
        },
    )
    status, headers, _ = call(secured, evt)
    assert status == 204
    assert headers["access-control-allow-origin"] == "https://app.example.com"
    assert "mcp-param-region" in headers["access-control-allow-headers"]
    assert "access-control-allow-credentials" not in headers


def test_preflight_from_foreign_origin_or_bad_headers(secured: McpLambdaHandler) -> None:
    assert (
        call(secured, event(method="OPTIONS", headers={"origin": "https://evil.example.com"}))[0]
        == 403
    )
    assert call(secured, event(method="OPTIONS"))[0] == 403
    evt = event(
        method="OPTIONS",
        headers={"origin": "https://app.example.com", "access-control-request-headers": "x\r\ny"},
    )
    assert call(secured, evt)[0] == 400


# --------------------------------------------------------------------------- #
# Authentication
# --------------------------------------------------------------------------- #
def test_missing_token_gets_a_401_challenge(secured: McpLambdaHandler) -> None:
    status, headers, body = call(secured, event(initialize()))
    assert status == 401
    challenge = headers["www-authenticate"]
    assert challenge.startswith("Bearer ")
    assert f'resource_metadata="{METADATA.metadata_url}"' in challenge
    assert 'scope="notes:read admin"' in challenge
    assert "error=" not in challenge  # RFC 6750: no error code without credentials
    assert body["error"]["code"] == -32001


def test_expired_token_gets_invalid_token(secured: McpLambdaHandler) -> None:
    status, headers, _ = call(
        secured, event(initialize(), token=make_token(exp=int(time.time()) - 999))
    )
    assert status == 401
    assert 'error="invalid_token"' in headers["www-authenticate"]
    assert 'error_description="token expired"' in headers["www-authenticate"]


@pytest.mark.parametrize(
    "header", ["Basic dXNlcjpwYXNz", "Bearer", "Bearer a b", "Bearer a,Bearer b", "Token abc"]
)
def test_malformed_authorization_headers(secured: McpLambdaHandler, header: str) -> None:
    status, headers, _ = call(secured, event(initialize(), headers={"authorization": header}))
    assert status == 401
    assert 'error="invalid_request"' in headers["www-authenticate"]


@pytest.mark.parametrize("param", ["access_token", "token", "id_token"])
def test_token_in_query_string_is_refused(secured: McpLambdaHandler, param: str) -> None:
    status, _, body = call(secured, event(initialize(), query=f"{param}={make_token()}"))
    assert status == 400
    assert "URL" in body["error"]["message"]


def test_valid_token_reaches_tools_as_principal(secured: McpLambdaHandler) -> None:
    status, _, body = call(
        secured, event(tool_call("whoami"), headers=V, token=make_token(scope="notes:read"))
    )
    assert status == 200
    assert body["result"]["structuredContent"] == {
        "sub": "alice",
        "scopes": ["notes:read"],
        "anonymous": False,
    }


def test_token_for_another_resource_is_refused(secured: McpLambdaHandler) -> None:
    token = make_token(aud="https://another-mcp.example.com/mcp")
    status, headers, _ = call(secured, event(initialize(), token=token))
    assert status == 401
    assert "invalid audience" in headers["www-authenticate"]


# --------------------------------------------------------------------------- #
# Scopes -> tools
# --------------------------------------------------------------------------- #
def test_tools_list_is_filtered_per_token(secured: McpLambdaHandler) -> None:
    _, _, body = call(
        secured, event(rpc("tools/list"), headers=V, token=make_token(scope="notes:read"))
    )
    assert sorted(t["name"] for t in body["result"]["tools"]) == ["echo", "whoami"]
    _, _, body = call(secured, event(rpc("tools/list"), headers=V, token=make_token(scope="admin")))
    assert sorted(t["name"] for t in body["result"]["tools"]) == ["admin_reset", "echo", "whoami"]
    _, _, body = call(secured, event(rpc("tools/list"), headers=V, token=make_token(scope="other")))
    assert body["result"]["tools"] == []


def test_modern_tools_list_is_private_cache(secured: McpLambdaHandler) -> None:
    headers = {"mcp-protocol-version": MODERN, "mcp-method": "tools/list"}
    _, _, body = call(
        secured,
        event(
            rpc("tools/list", {"_meta": MODERN_META}),
            headers=headers,
            token=make_token(scope="notes:read"),
        ),
    )
    assert sorted(t["name"] for t in body["result"]["tools"]) == ["echo", "whoami"]
    assert body["result"].get("cacheScope", "private") == "private"


def test_disallowed_tool_call_is_403_insufficient_scope(secured: McpLambdaHandler) -> None:
    status, headers, body = call(
        secured,
        event(tool_call("admin_reset", msg_id=7), headers=V, token=make_token(scope="notes:read")),
    )
    assert status == 403
    challenge = headers["www-authenticate"]
    assert 'error="insufficient_scope"' in challenge
    assert 'scope="admin"' in challenge
    assert "resource_metadata=" in challenge
    assert body["id"] == 7 and body["error"]["code"] == -32003


def test_unknown_tool_is_denied_by_default(secured: McpLambdaHandler) -> None:
    status, headers, _ = call(
        secured, event(tool_call("ghost"), headers=V, token=make_token(scope="notes:read"))
    )
    assert status == 403
    # Only the wildcard admin scope could grant an unknown tool.
    assert 'scope="admin"' in headers["www-authenticate"]


def test_admin_scope_grants_everything(secured: McpLambdaHandler) -> None:
    status, _, body = call(
        secured, event(tool_call("admin_reset"), headers=V, token=make_token(scope="admin"))
    )
    assert status == 200
    assert body["result"]["content"][0]["text"] == "reset"


def test_without_a_policy_every_authenticated_caller_may_call_every_tool(
    verifier: JWTVerifier,
) -> None:
    handler = lambda_handler_for(
        make_server(), auth=BearerAuth(verifier), resource_metadata=METADATA
    )
    status, _, _ = call(
        handler, event(tool_call("admin_reset"), headers=V, token=make_token(scope=""))
    )
    assert status == 200


# --------------------------------------------------------------------------- #
# Protected resource metadata
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "path", ["/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-protected-resource"]
)
def test_metadata_is_public(secured: McpLambdaHandler, path: str) -> None:
    status, headers, body = call(secured, event(method="GET", path=path))
    assert status == 200
    assert body == {
        "resource": RESOURCE,
        "authorization_servers": [ISSUER],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["notes:read", "admin"],
    }
    assert headers["access-control-allow-origin"] == "*"
    assert headers["cache-control"].startswith("public")


def test_metadata_head_options_and_post(secured: McpLambdaHandler) -> None:
    path = "/.well-known/oauth-protected-resource"
    result = secured(event(method="HEAD", path=path), None)
    assert result["statusCode"] == 200 and result["body"] == ""
    assert call(secured, event(method="OPTIONS", path=path))[0] == 204
    assert call(secured, event(method="POST", path=path))[0] == 405


def test_no_metadata_on_an_anonymous_server(anon: McpLambdaHandler) -> None:
    assert call(anon, event(method="GET", path="/.well-known/oauth-protected-resource"))[0] == 404


# --------------------------------------------------------------------------- #
# Configuration guards
# --------------------------------------------------------------------------- #
def test_auth_is_required_unless_explicitly_anonymous() -> None:
    with pytest.raises(ValueError, match="no authentication"):
        lambda_handler_for(make_server())


def test_auth_and_anonymous_are_exclusive(verifier: JWTVerifier) -> None:
    with pytest.raises(ValueError, match="mutually exclusive"):
        lambda_handler_for(
            make_server(),
            auth=BearerAuth(verifier),
            allow_anonymous=True,
            resource_metadata=METADATA,
        )


def test_auth_needs_metadata(verifier: JWTVerifier) -> None:
    with pytest.raises(ValueError, match="protected resource metadata"):
        lambda_handler_for(make_server(), auth=BearerAuth(verifier))


def test_policy_needs_auth() -> None:
    with pytest.raises(ValueError, match="tool_policy"):
        lambda_handler_for(make_server(), allow_anonymous=True, tool_policy=POLICY)


def test_audience_must_include_the_resource(jwks: Any) -> None:
    other = JWTVerifier(
        issuer=ISSUER, audience="https://other.example.com", jwks_url=JWKS_URL, fetcher=jwks
    )
    with pytest.raises(ValueError, match="RFC 8707"):
        lambda_handler_for(make_server(), auth=BearerAuth(other), resource_metadata=METADATA)


@pytest.mark.parametrize("path", ["mcp", "/mcp/", "/a/./b"])
def test_bad_mcp_path(path: str) -> None:
    with pytest.raises(ValueError):
        lambda_handler_for(make_server(), allow_anonymous=True, mcp_path=path)


def test_bad_limits() -> None:
    with pytest.raises(ValueError):
        lambda_handler_for(make_server(), allow_anonymous=True, max_batch_size=0)


def test_sdk_auth_on_the_server_is_refused() -> None:
    from mcp.server.auth.provider import AccessToken
    from mcp.server.auth.settings import AuthSettings
    from mcp.server.mcpserver import MCPServer

    class V:
        async def verify_token(self, token: str) -> AccessToken | None:
            return None

    server = MCPServer(
        "x",
        token_verifier=V(),
        auth=AuthSettings(
            issuer_url=ISSUER,  # type: ignore[arg-type]
            resource_server_url=RESOURCE,  # type: ignore[arg-type]
            validate_token_resource=True,
        ),
    )
    with pytest.raises(ValueError, match="not on the MCPServer"):
        lambda_handler_for(server, allow_anonymous=True)


def test_server_type_is_checked() -> None:
    with pytest.raises(TypeError):
        lambda_handler_for(object(), allow_anonymous=True)  # type: ignore[arg-type]


def test_custom_mcp_path(verifier: JWTVerifier) -> None:
    metadata = ProtectedResourceMetadata.create("https://x.example.com/tools/mcp", [ISSUER])
    v = JWTVerifier(
        issuer=ISSUER, audience=metadata.resource, jwks_url=JWKS_URL, fetcher=verifier.jwks._fetch
    )
    handler = lambda_handler_for(
        make_server(), auth=BearerAuth(v), resource_metadata=metadata, mcp_path="/tools/mcp"
    )
    token = make_token(aud=metadata.resource)
    assert call(handler, event(initialize(), path="/tools/mcp", token=token))[0] == 200
    assert (
        call(handler, event(method="GET", path="/.well-known/oauth-protected-resource/tools/mcp"))[
            0
        ]
        == 200
    )


def test_access_log_line_has_no_payload(
    anon: McpLambdaHandler, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="serverless_mcp_aws"):
        call(anon, event(tool_call("echo", {"text": "very-private-text"}), headers=V))
        call(anon, event(rpc("weird\nmethod"), headers=V))
    text = caplog.text
    assert "mcp POST tools/call -> 200" in text
    assert "very-private-text" not in text
    assert "weird\nmethod" not in text
