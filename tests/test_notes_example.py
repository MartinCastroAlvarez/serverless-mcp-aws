"""The notes example: tools backed by a moto S3 bucket, per-caller isolation."""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from typing import Any

import boto3
import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from moto import mock_aws

from examples.notes import app as notes
from examples.notes import authorizer as notes_authorizer
from serverless_mcp_aws import JWTVerifier
from serverless_mcp_aws.dev import DevServer
from tests.conftest import ISSUER
from tests.conftest import JWKS_URL
from tests.conftest import RESOURCE
from tests.conftest import FakeJWKS
from tests.conftest import body_of
from tests.conftest import event
from tests.conftest import make_token
from tests.conftest import rpc

ENV = {
    "MCP_RESOURCE": RESOURCE,
    "MCP_AUTHORIZATION_SERVERS": ISSUER,
    "MCP_SCOPES": "notes:read notes:write",
    "MCP_JWT_ISSUER": ISSUER,
    "MCP_JWT_JWKS_URL": JWKS_URL,
}


@pytest.fixture
def bucket(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    monkeypatch.setenv("NOTES_BUCKET", "notes-test")
    notes._s3.cache_clear()
    with mock_aws():
        boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="notes-test")
        yield "notes-test"
    notes._s3.cache_clear()


@pytest.fixture
def handler(bucket: str, jwks: FakeJWKS, monkeypatch: pytest.MonkeyPatch) -> Any:
    built = notes.build_handler(ENV)
    assert built.auth is not None
    built.auth.verifier.jwks._fetch = jwks  # type: ignore[attr-defined]
    return built


async def use(url: str, token: str, script: Any) -> Any:
    headers = {"authorization": f"Bearer {token}"}
    async with httpx2.AsyncClient(headers=headers, timeout=10) as http:
        transport = streamable_http_client(url, http_client=http)
        async with Client(transport) as client:
            return await script(client)


def test_notes_end_to_end_with_isolation(handler: Any, bucket: str) -> None:
    writer = make_token(sub="alice", scope="notes:write")
    other = make_token(sub="mallory", scope="notes:read notes:write")

    async def add_and_list(client: Client) -> Any:
        added = await client.call_tool("add_note", {"title": "Groceries", "body": "milk"})
        note_id = added.structured_content["id"]  # type: ignore[index]
        listed = await client.call_tool("list_notes", {})
        read = await client.call_tool("read_note", {"note_id": note_id})
        return note_id, listed.structured_content, read.structured_content

    def snoop(note_id: str) -> Any:
        async def inner(client: Client) -> Any:
            listed = await client.call_tool("list_notes", {})
            stolen = await client.call_tool("read_note", {"note_id": note_id})
            traversal = await client.call_tool("read_note", {"note_id": "../" + note_id})
            return listed.structured_content, stolen.is_error, traversal.is_error

        return inner

    with DevServer(handler, port=0) as dev:
        note_id, listed, read = asyncio.run(use(f"{dev.url}/mcp", writer, add_and_list))
        assert listed == {"result": [{"id": note_id, "title": "Groceries"}]}
        assert read["body"] == "milk" and read["untrusted_content"] is True
        theirs, stolen_is_error, traversal_is_error = asyncio.run(
            use(f"{dev.url}/mcp", other, snoop(note_id))
        )
    assert theirs == {"result": []}
    assert stolen_is_error and traversal_is_error

    keys = [o["Key"] for o in boto3.client("s3").list_objects_v2(Bucket=bucket)["Contents"]]
    assert len(keys) == 1
    assert keys[0].startswith("notes/") and "alice" not in keys[0]


def test_read_scope_cannot_write(handler: Any) -> None:
    token = make_token(scope="notes:read")
    headers = {"mcp-protocol-version": "2025-11-25"}
    listed = handler(event(rpc("tools/list"), headers=headers, token=token), None)
    assert sorted(t["name"] for t in body_of(listed)["result"]["tools"]) == [
        "list_notes",
        "read_note",
    ]
    denied = handler(
        event(
            rpc("tools/call", {"name": "add_note", "arguments": {"title": "x", "body": "y"}}),
            headers=headers,
            token=token,
        ),
        None,
    )
    assert denied["statusCode"] == 403
    assert 'scope="notes:write"' in denied["headers"]["www-authenticate"]


@pytest.mark.parametrize(
    ("args", "message"),
    [({"title": "", "body": "x"}, "title"), ({"title": "t", "body": "x" * 20000}, "body")],
)
def test_validation(handler: Any, args: dict[str, str], message: str) -> None:
    token = make_token(scope="notes:write")
    result = handler(
        event(
            rpc("tools/call", {"name": "add_note", "arguments": args}),
            headers={"mcp-protocol-version": "2025-11-25"},
            token=token,
        ),
        None,
    )
    body = body_of(result)
    assert body["result"]["isError"] is True
    assert message in body["result"]["content"][0]["text"]


def test_build_handler_modes(bucket: str) -> None:
    assert notes.build_handler({"NOTES_AUTH": "none"}).auth is None
    from serverless_mcp_aws import AuthorizerContextAuth

    assert isinstance(
        notes.build_handler({**ENV, "NOTES_AUTH": "authorizer"}).auth, AuthorizerContextAuth
    )


def test_lambda_entry_points(bucket: str, monkeypatch: pytest.MonkeyPatch, jwks: FakeJWKS) -> None:
    monkeypatch.setattr(notes, "_handler", None)
    monkeypatch.setenv("NOTES_AUTH", "none")
    result = notes.handler(
        event(
            rpc("tools/call", {"name": "list_notes", "arguments": {}}),
            headers={"mcp-protocol-version": "2025-11-25"},
        ),
        None,
    )
    assert result["statusCode"] == 200
    for key, value in ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(notes_authorizer, "_handler", None)
    monkeypatch.setattr(
        JWTVerifier,
        "from_env",
        classmethod(
            lambda cls, env=None: JWTVerifier(
                issuer=ISSUER, audience=RESOURCE, jwks_url=JWKS_URL, fetcher=jwks
            )
        ),
    )
    decision = notes_authorizer.handler(
        {"headers": {"authorization": f"Bearer {make_token()}"}}, None
    )
    assert decision["isAuthorized"] is True


def test_missing_bucket_is_a_tool_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NOTES_BUCKET", raising=False)
    with pytest.raises(RuntimeError):
        notes._bucket()
