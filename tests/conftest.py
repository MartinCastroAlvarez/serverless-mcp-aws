"""Shared fixtures: locally generated keys, token minting, API Gateway events."""

from __future__ import annotations

import base64
import json
import os
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp.server.mcpserver import MCPServer

from serverless_mcp_aws import JWTVerifier
from serverless_mcp_aws import ProtectedResourceMetadata
from serverless_mcp_aws import ToolPolicy
from serverless_mcp_aws import current_principal

ISSUER = "https://auth.example.com"
RESOURCE = "https://mcp.example.com/mcp"
JWKS_URL = "https://auth.example.com/.well-known/jwks.json"
EVENTS = Path(__file__).parent / "events"

# No test may ever reach AWS: moto and fakes only.
os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")

RSA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
RSA_KEY_2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
EC_KEY = ec.generate_private_key(ec.SECP256R1())


def public_jwk(key: Any, kid: str, alg: str | None) -> dict[str, Any]:
    if isinstance(key, rsa.RSAPrivateKey):
        doc = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    else:
        doc = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
    doc["kid"] = kid
    doc["use"] = "sig"
    if alg:
        doc["alg"] = alg
    return dict(doc)


class FakeJWKS:
    """A JWKS endpoint that counts fetches."""

    def __init__(self, keys: list[dict[str, Any]]) -> None:
        self.keys = keys
        self.calls = 0
        self.fail = False

    def __call__(self, url: str) -> bytes:
        assert url == JWKS_URL
        self.calls += 1
        if self.fail:
            raise OSError("down")
        return json.dumps({"keys": self.keys}).encode()


@pytest.fixture
def jwks() -> FakeJWKS:
    return FakeJWKS([public_jwk(RSA_KEY, "rsa-1", "RS256"), public_jwk(EC_KEY, "ec-1", "ES256")])


@pytest.fixture
def verifier(jwks: FakeJWKS) -> JWTVerifier:
    return JWTVerifier(issuer=ISSUER, audience=RESOURCE, jwks_url=JWKS_URL, fetcher=jwks)


def claims(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    base: dict[str, Any] = {
        "iss": ISSUER,
        "aud": RESOURCE,
        "sub": "alice",
        "iat": now,
        "exp": now + 300,
        "scope": "notes:read notes:write",
        "client_id": "cli-1",
    }
    base.update(overrides)
    return {k: v for k, v in base.items() if v is not None}


def make_token(
    alg: str = "RS256",
    kid: str | None = "rsa-1",
    key: Any = None,
    headers: dict[str, Any] | None = None,
    **claim_overrides: Any,
) -> str:
    if key is None:
        key = RSA_KEY if alg[:2] in ("RS", "PS") else EC_KEY
    hdrs = dict(headers or {})
    if kid is not None:
        hdrs["kid"] = kid
    return jwt.encode(claims(**claim_overrides), key, algorithm=alg, headers=hdrs)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def event(
    body: Any = None,
    *,
    method: str = "POST",
    path: str = "/mcp",
    headers: dict[str, str] | None = None,
    token: str | None = None,
    query: str = "",
    raw_body: str | None = None,
    base64_body: bool = False,
    authorizer: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """A payload-2.0 event, built from the captured sample in tests/events/."""
    evt: dict[str, Any] = json.loads((EVENTS / "post_mcp.json").read_text())
    evt["rawPath"] = path
    evt["requestContext"]["http"]["path"] = path
    evt["requestContext"]["http"]["method"] = method
    evt["rawQueryString"] = query
    hdrs = {
        "accept": "application/json, text/event-stream",
        "content-type": "application/json",
        "host": "abc123.execute-api.us-east-1.amazonaws.com",
    }
    if token:
        hdrs["authorization"] = f"Bearer {token}"
    hdrs.update(headers or {})
    evt["headers"] = hdrs
    if raw_body is not None:
        evt["body"] = raw_body
    elif body is not None:
        evt["body"] = json.dumps(body)
    else:
        evt.pop("body", None)
    if base64_body and "body" in evt:
        evt["body"] = base64.b64encode(evt["body"].encode()).decode()
        evt["isBase64Encoded"] = True
    else:
        evt["isBase64Encoded"] = False
    if authorizer is not None:
        evt["requestContext"]["authorizer"] = authorizer
    return evt


def rpc(
    method: str, params: dict[str, Any] | None = None, msg_id: int | None = 1
) -> dict[str, Any]:
    msg: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    if msg_id is not None:
        msg["id"] = msg_id
    return msg


LEGACY = "2025-11-25"
MODERN = "2026-07-28"
MODERN_META = {
    "io.modelcontextprotocol/protocolVersion": MODERN,
    "io.modelcontextprotocol/clientInfo": {"name": "tests", "version": "1"},
    "io.modelcontextprotocol/clientCapabilities": {},
}


def initialize() -> dict[str, Any]:
    return rpc(
        "initialize",
        {
            "protocolVersion": LEGACY,
            "capabilities": {},
            "clientInfo": {"name": "tests", "version": "1"},
        },
    )


def make_server() -> MCPServer:
    server = MCPServer("demo")

    @server.tool()
    def echo(text: str) -> str:
        """Echo text back."""
        return text

    @server.tool()
    def whoami() -> dict[str, Any]:
        """Return the caller."""
        p = current_principal()
        return {"sub": p.subject, "scopes": sorted(p.scopes), "anonymous": p.anonymous}

    @server.tool()
    def admin_reset() -> str:
        """Dangerous."""
        return "reset"

    return server


POLICY = ToolPolicy({"notes:read": ["echo", "whoami"], "admin": ["*"]})
METADATA = ProtectedResourceMetadata.create(RESOURCE, [ISSUER], ["notes:read", "admin"])


def body_of(result: dict[str, Any]) -> Any:
    raw = result.get("body") or ""
    if result.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode()
    return json.loads(raw) if raw else None


Mint = Callable[..., str]
