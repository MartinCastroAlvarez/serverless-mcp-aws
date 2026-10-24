"""End to end: the official MCP client against the local dev server.

The dev server turns real HTTP requests into API Gateway events and runs the
same handler Lambda would, so these tests cover the whole path a deployed
server takes, offline.
"""

from __future__ import annotations

import asyncio
import json
import sys
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx2
import pytest
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from serverless_mcp_aws import AuthorizerContextAuth
from serverless_mcp_aws import BearerAuth
from serverless_mcp_aws import JWTVerifier
from serverless_mcp_aws import authorizer_handler_for
from serverless_mcp_aws import lambda_handler_for
from serverless_mcp_aws.cli import main
from serverless_mcp_aws.dev import DevServer
from serverless_mcp_aws.dev import as_handler
from serverless_mcp_aws.dev import load_target
from serverless_mcp_aws.dev import make_event
from tests.conftest import METADATA
from tests.conftest import POLICY
from tests.conftest import make_server
from tests.conftest import make_token


@pytest.fixture
def anon_server() -> Iterator[DevServer]:
    with DevServer(as_handler(make_server()), port=0) as dev:
        yield dev


def http_status(req: urllib.request.Request | str) -> tuple[int, Any]:
    """Status and headers of a request to the loopback dev server (sockets closed)."""
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.headers
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, exc.headers


def run(coro: Any) -> Any:
    return asyncio.run(coro)


async def session(url: str, mode: str, token: str | None = None) -> dict[str, Any]:
    headers = {"authorization": f"Bearer {token}"} if token else {}
    async with httpx2.AsyncClient(headers=headers, timeout=10) as http:
        transport = streamable_http_client(url, http_client=http)
        async with Client(transport, mode=mode) as client:
            tools = await client.list_tools()
            echo = await client.call_tool("echo", {"text": "hello"})
            who = await client.call_tool("whoami", {})
            return {
                "version": client.protocol_version,
                "tools": sorted(t.name for t in tools.tools),
                "echo": echo.content[0].text,  # type: ignore[union-attr]
                "who": who.structured_content,
            }


@pytest.mark.parametrize(("mode", "version"), [("auto", "2026-07-28"), ("legacy", "2025-11-25")])
def test_client_against_anonymous_dev_server(
    anon_server: DevServer, mode: str, version: str
) -> None:
    out = run(session(f"{anon_server.url}/mcp", mode))
    assert out["version"] == version
    assert out["tools"] == ["admin_reset", "echo", "whoami"]
    assert out["echo"] == "hello"
    assert out["who"]["anonymous"] is True


@pytest.mark.parametrize("mode", ["auto", "legacy"])
def test_client_with_jwt_and_scopes(verifier: JWTVerifier, mode: str) -> None:
    handler = lambda_handler_for(
        make_server(), auth=BearerAuth(verifier), resource_metadata=METADATA, tool_policy=POLICY
    )
    with DevServer(handler, port=0) as dev:
        out = run(session(f"{dev.url}/mcp", mode, make_token(scope="notes:read")))
    assert out["tools"] == ["echo", "whoami"]
    assert out["who"] == {"sub": "alice", "scopes": ["notes:read"], "anonymous": False}


def test_client_without_token_is_refused(verifier: JWTVerifier) -> None:
    handler = lambda_handler_for(
        make_server(), auth=BearerAuth(verifier), resource_metadata=METADATA
    )
    with DevServer(handler, port=0) as dev:
        for mode in ("legacy", "auto"):
            with pytest.raises(ExceptionGroup):
                run(session(f"{dev.url}/mcp", mode))
        status, headers = http_status(
            urllib.request.Request(f"{dev.url}/mcp", data=b"{}", method="POST")
        )
        assert status == 401
        assert "resource_metadata=" in headers["www-authenticate"]
        with urllib.request.urlopen(
            f"{dev.url}/.well-known/oauth-protected-resource/mcp", timeout=5
        ) as resp:
            assert json.load(resp)["resource"] == METADATA.resource


def test_client_through_emulated_lambda_authorizer(verifier: JWTVerifier) -> None:
    handler = lambda_handler_for(
        make_server(), auth=AuthorizerContextAuth(), resource_metadata=METADATA, tool_policy=POLICY
    )
    with DevServer(handler, port=0, authorizer=authorizer_handler_for(verifier)) as dev:
        out = run(session(f"{dev.url}/mcp", "auto", make_token(scope="notes:read")))
        assert out["who"]["sub"] == "alice"
        for headers, status in (({}, 401), ({"authorization": "Bearer bad.to.ken"}, 403)):
            req = urllib.request.Request(
                f"{dev.url}/mcp", data=b"{}", method="POST", headers=headers
            )
            assert http_status(req)[0] == status
        # Metadata and preflight stay public, as in the CDK construct.
        assert http_status(f"{dev.url}/.well-known/oauth-protected-resource")[0] == 200


def test_dev_server_http_details(anon_server: DevServer) -> None:
    assert http_status(urllib.request.Request(f"{anon_server.url}/mcp", method="GET"))[0] == 405
    assert http_status(urllib.request.Request(f"{anon_server.url}/mcp", method="HEAD"))[0] == 405
    # A browser page on another origin is refused (DNS rebinding).
    req = urllib.request.Request(
        f"{anon_server.url}/mcp", data=b"{}", method="POST", headers={"Origin": "http://evil.test"}
    )
    assert http_status(req)[0] == 403


def test_make_event_shape() -> None:
    evt = make_event(
        method="POST",
        target="/mcp?a=1",
        headers=[("X-A", "1"), ("x-a", "2"), ("Cookie", "a=1; b=2")],
        body=b"\xff",
    )
    assert evt["version"] == "2.0"
    assert evt["rawQueryString"] == "a=1"
    assert evt["headers"]["x-a"] == "1,2"
    assert evt["cookies"] == ["a=1", "b=2"]
    assert evt["isBase64Encoded"] is True and evt["body"] == "/w=="


def test_load_target(tmp_path: Path) -> None:
    (tmp_path / "devapp_target.py").write_text(
        "from mcp.server.mcpserver import MCPServer\nserver = MCPServer('t')\n"
    )
    server = load_target("devapp_target:server", search_path=tmp_path)
    assert callable(as_handler(server))
    with pytest.raises(ValueError):
        load_target("devapp_target:missing", search_path=tmp_path)
    with pytest.raises(ValueError):
        load_target("not a target")
    with pytest.raises(TypeError):
        as_handler(42)
    sys.modules.pop("devapp_target", None)


def test_cli_refuses_remote_bind(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["dev", "x:y", "--host", "0.0.0.0"]) == 2
    assert "refusing" in capsys.readouterr().err


def test_cli_bad_target(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["dev", "no_such_module_xyz:server", "--port", "0"]) == 2
    assert "error" in capsys.readouterr().err


def test_cli_serves_until_interrupted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "cliapp_target.py").write_text(
        "from mcp.server.mcpserver import MCPServer\nserver = MCPServer('t')\n"
    )
    monkeypatch.chdir(tmp_path)

    def interrupted(self: DevServer) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(DevServer, "serve_forever", interrupted)
    assert (
        main(["dev", "cliapp_target:server", "--port", "0", "--authorizer", "cliapp_target:server"])
        == 0
    )
    assert "serving cliapp_target:server" in capsys.readouterr().err
    sys.modules.pop("cliapp_target", None)


def test_cli_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        main(["--version"])
    assert "serverless-mcp-aws" in capsys.readouterr().out
