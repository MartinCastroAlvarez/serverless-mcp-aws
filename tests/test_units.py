"""Small building blocks: events, origins, policy, metadata, principals, authenticators."""

from __future__ import annotations

import time

import pytest

from serverless_mcp_aws import ANONYMOUS
from serverless_mcp_aws import AuthError
from serverless_mcp_aws import AuthorizerContextAuth
from serverless_mcp_aws import OriginPolicy
from serverless_mcp_aws import Principal
from serverless_mcp_aws import ProtectedResourceMetadata
from serverless_mcp_aws import ToolPolicy
from serverless_mcp_aws import current_principal
from serverless_mcp_aws import principal_scope
from serverless_mcp_aws.auth.metadata import challenge
from serverless_mcp_aws.events import HttpRequest
from serverless_mcp_aws.events import HttpResponse
from serverless_mcp_aws.jsonrpc import is_notification
from serverless_mcp_aws.jsonrpc import is_request
from serverless_mcp_aws.jsonrpc import request_id
from tests.conftest import ISSUER
from tests.conftest import RESOURCE
from tests.conftest import event


# --------------------------------------------------------------------------- #
# Events
# --------------------------------------------------------------------------- #
def test_event_parsing_lowercases_headers_and_reads_query() -> None:
    evt = event({"a": 1}, headers={"X-Thing": "v"}, query="a=1&a=2&b=")
    req = HttpRequest.from_event(evt, max_body_bytes=1000)
    assert req.header("x-thing") == "v"
    assert req.query == {"a": ["1", "2"], "b": [""]}
    assert req.source_ip == "203.0.113.7"
    assert req.method == "POST"


def test_binary_response_is_base64() -> None:
    out = HttpResponse(200, {}, b"\xff\xfe").to_lambda()
    assert out["isBase64Encoded"] is True and out["body"] == "//4="


def test_jsonrpc_classification() -> None:
    assert is_request({"method": "x", "id": 1})
    assert is_notification({"method": "x"})
    assert not is_request([1])
    assert request_id({"id": True}) is None
    assert request_id({"id": "a"}) == "a"
    assert request_id(3) is None


# --------------------------------------------------------------------------- #
# Origins
# --------------------------------------------------------------------------- #
def test_origin_policy() -> None:
    policy = OriginPolicy.of(["https://app.example.com", "http://localhost:*", "http://[::1]:*"])
    assert policy.allows(None)
    assert policy.allows("https://app.example.com")
    assert policy.allows("HTTPS://APP.EXAMPLE.COM")
    assert policy.allows("http://localhost:5173")
    assert policy.allows("http://[::1]:3000")
    assert not policy.allows("http://localhost")  # no port: not covered by :*
    assert not policy.allows("https://app.example.com.evil.com")
    assert not policy.allows("https://evil.com/https://app.example.com")
    assert not policy.allows("http://app.example.com")
    assert not policy.allows("null")
    assert not policy.allows("http://localhost:*")
    assert not policy.allows("javascript:alert(1)")


@pytest.mark.parametrize("bad", ["*", "app.example.com", "https://a.com/path", "ftp://a.com"])
def test_origin_policy_refuses_patterns(bad: str) -> None:
    with pytest.raises(ValueError):
        OriginPolicy.of([bad])


# --------------------------------------------------------------------------- #
# Tool policy
# --------------------------------------------------------------------------- #
def test_tool_policy() -> None:
    policy = ToolPolicy({"read": ["a", "b"], "write": ["c"], "root": ["*"]})
    reader = Principal(subject="x", scopes=frozenset({"read", "unknown"}))
    assert policy.allowed_tools(reader) == {"a", "b"}
    assert policy.allows(reader, "a") and not policy.allows(reader, "c")
    assert policy.allowed_tools(Principal(subject="x", scopes=frozenset({"root"}))) is None
    assert policy.scopes_for("c") == ("root", "write")
    assert policy.scopes == ("read", "root", "write")


def test_tool_policy_validation() -> None:
    with pytest.raises(ValueError):
        ToolPolicy({'bad"scope': ["a"]})
    with pytest.raises(TypeError):
        ToolPolicy({"read": "a"})


# --------------------------------------------------------------------------- #
# Metadata and challenges
# --------------------------------------------------------------------------- #
def test_metadata_paths_and_url() -> None:
    meta = ProtectedResourceMetadata.create(
        RESOURCE + "/",
        [ISSUER],
        ["s"],
        resource_name="Notes",
        resource_documentation="https://d.example.com",
    )
    assert meta.resource == RESOURCE
    assert meta.metadata_url == "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
    assert meta.paths() == (
        "/.well-known/oauth-protected-resource/mcp",
        "/.well-known/oauth-protected-resource",
    )
    doc = meta.to_dict()
    assert doc["resource_name"] == "Notes"
    assert doc["resource_documentation"] == "https://d.example.com"


def test_metadata_at_the_root() -> None:
    meta = ProtectedResourceMetadata.create("https://mcp.example.com", [ISSUER])
    assert meta.paths() == ("/.well-known/oauth-protected-resource",)
    assert meta.metadata_url == "https://mcp.example.com/.well-known/oauth-protected-resource"


@pytest.mark.parametrize(
    ("resource", "servers", "scopes"),
    [
        ("http://mcp.example.com/mcp", [ISSUER], []),
        ("https://mcp.example.com/mcp#frag", [ISSUER], []),
        ("mcp.example.com", [ISSUER], []),
        (RESOURCE, [], []),
        (RESOURCE, ["http://auth.example.com"], []),
        (RESOURCE, [ISSUER], ["offline_access"]),
    ],
)
def test_metadata_validation(resource: str, servers: list[str], scopes: list[str]) -> None:
    with pytest.raises(ValueError):
        ProtectedResourceMetadata.create(resource, servers, scopes)


def test_metadata_localhost_http_is_allowed() -> None:
    meta = ProtectedResourceMetadata.create("http://localhost:8000/mcp", ["http://localhost:9000"])
    assert meta.resource == "http://localhost:8000/mcp"


def test_metadata_from_env() -> None:
    meta = ProtectedResourceMetadata.from_env(
        {
            "MCP_RESOURCE": RESOURCE,
            "MCP_AUTHORIZATION_SERVERS": f"{ISSUER}, https://b.example.com",
            "MCP_SCOPES": "a b",
        }
    )
    assert meta.authorization_servers == (ISSUER, "https://b.example.com")
    assert meta.scopes_supported == ("a", "b")
    with pytest.raises(ValueError, match="MCP_RESOURCE"):
        ProtectedResourceMetadata.from_env({})


def test_challenge_drops_unsafe_values() -> None:
    assert challenge(resource_metadata=None) == "Bearer"
    value = challenge(
        resource_metadata='https://x"injected', error="invalid_token", description="bad\r\nX: y"
    )
    assert value == 'Bearer error="invalid_token"'


# --------------------------------------------------------------------------- #
# Principals
# --------------------------------------------------------------------------- #
def test_current_principal_outside_a_request() -> None:
    with pytest.raises(LookupError):
        current_principal()
    with principal_scope(ANONYMOUS):
        assert current_principal().anonymous
    with pytest.raises(LookupError):
        current_principal()


def test_principal_key_separates_issuers() -> None:
    a = Principal(subject="alice", issuer="https://a.example.com")
    b = Principal(subject="alice", issuer="https://b.example.com")
    assert a.key != b.key
    assert a.has_scope("x") is False


# --------------------------------------------------------------------------- #
# AuthorizerContextAuth
# --------------------------------------------------------------------------- #
def _req(authorizer: dict[str, object]) -> HttpRequest:
    return HttpRequest.from_event(event({}, authorizer=authorizer), max_body_bytes=1000)


def test_lambda_authorizer_context() -> None:
    auth = AuthorizerContextAuth()
    exp = int(time.time()) + 60
    p = auth.authenticate(
        _req(
            {
                "lambda": {
                    "sub": "bob",
                    "scope": "a b",
                    "iss": ISSUER,
                    "client_id": "c",
                    "exp": exp,
                    "aud": RESOURCE,
                }
            }
        )
    )
    assert (p.subject, p.scopes, p.client_id, p.expires_at, p.audience) == (
        "bob",
        {"a", "b"},
        "c",
        exp,
        (RESOURCE,),
    )


def test_jwt_authorizer_context() -> None:
    auth = AuthorizerContextAuth("jwt")
    p = auth.authenticate(
        _req({"jwt": {"claims": {"sub": "bob", "scope": "[a b]", "azp": "web"}, "scopes": None}})
    )
    assert p.scopes == {"a", "b"} and p.client_id == "web"
    p = auth.authenticate(_req({"jwt": {"claims": {"sub": "bob", "scp": ["x", 1]}}}))
    assert p.scopes == {"x"}
    p = auth.authenticate(_req({"jwt": {"claims": {"sub": "bob", "scope": 3}}}))
    assert p.scopes == frozenset()
    with pytest.raises(AuthError):
        auth.authenticate(_req({"jwt": {"claims": "nope"}}))


@pytest.mark.parametrize(
    "ctx",
    [
        {},
        {"lambda": "x"},
        {"lambda": {"scope": "a"}},
        {"lambda": {"sub": "bob", "exp": 1}},
        {"lambda": {"sub": "bob", "exp": "soon"}},
    ],
)
def test_authorizer_context_fails_closed(ctx: dict[str, object]) -> None:
    with pytest.raises(AuthError):
        AuthorizerContextAuth().authenticate(_req(ctx))


def test_authorizer_context_source_is_validated() -> None:
    with pytest.raises(ValueError):
        AuthorizerContextAuth("cognito")  # type: ignore[arg-type]
