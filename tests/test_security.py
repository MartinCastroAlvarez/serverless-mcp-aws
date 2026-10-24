"""Security properties that are easy to lose in a refactor."""

from __future__ import annotations

import ast
import logging
from pathlib import Path
from typing import Any

import pytest
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.mcpserver import Context
from mcp.server.mcpserver import MCPServer

from serverless_mcp_aws import BearerAuth
from serverless_mcp_aws import JWTVerifier
from serverless_mcp_aws import lambda_handler_for
from tests.conftest import METADATA
from tests.conftest import body_of
from tests.conftest import event
from tests.conftest import make_token
from tests.conftest import rpc

PACKAGE = Path(__file__).resolve().parent.parent / "serverless_mcp_aws"
FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__"}
FORBIDDEN_MODULES = {"pickle", "marshal", "shelve", "subprocess", "yaml"}


def _modules() -> list[Path]:
    return sorted(PACKAGE.rglob("*.py"))


@pytest.mark.parametrize("path", _modules(), ids=lambda p: p.name)
def test_no_dangerous_constructs(path: Path) -> None:
    tree = ast.parse(path.read_text(), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in FORBIDDEN_CALLS, f"{path.name}:{node.lineno}"
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] not in FORBIDDEN_MODULES, (
                    f"{path.name}:{node.lineno}"
                )
        if isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] not in FORBIDDEN_MODULES, f"{path.name}:{node.lineno}"
        if isinstance(node, ast.keyword) and node.arg == "shell":
            raise AssertionError(f"shell= in {path.name}:{node.lineno}")


@pytest.mark.parametrize("path", _modules(), ids=lambda p: p.name)
def test_no_suppressions_in_the_package(path: Path) -> None:
    text = path.read_text()
    for marker in ("# noqa", "# nosec", "# type: ignore"):
        assert marker not in text, f"{marker} in {path.name}"


def leaky_server() -> MCPServer:
    server = MCPServer("leaky")

    @server.tool()
    def headers(ctx: Context) -> dict[str, Any]:
        """What a (possibly malicious) tool can see of the HTTP request."""
        request = ctx.request_context.request
        seen = dict(request.headers) if request is not None else {}  # type: ignore[union-attr]
        token = get_access_token()
        return {"headers": seen, "sdk_token": token.token if token else None}

    return server


def test_tools_never_see_the_bearer_token(
    verifier: JWTVerifier, caplog: pytest.LogCaptureFixture
) -> None:
    """Token passthrough is impossible: the token stops at the handler."""
    handler = lambda_handler_for(
        leaky_server(), auth=BearerAuth(verifier), resource_metadata=METADATA
    )
    token = make_token()
    with caplog.at_level(logging.DEBUG):
        result = handler(
            event(
                rpc("tools/call", {"name": "headers", "arguments": {}}),
                headers={
                    "mcp-protocol-version": "2025-11-25",
                    "cookie": "session=abc",
                    "mcp-session-id": "s1",
                },
                token=token,
            ),
            None,
        )
    seen = body_of(result)["result"]["structuredContent"]
    assert "authorization" not in seen["headers"]
    assert "cookie" not in seen["headers"]
    assert "mcp-session-id" not in seen["headers"]
    assert seen["sdk_token"] == ""
    assert token not in str(result)
    assert token not in caplog.text
    assert token.split(".")[2] not in caplog.text


def test_refused_tokens_are_not_logged(
    verifier: JWTVerifier, caplog: pytest.LogCaptureFixture
) -> None:
    handler = lambda_handler_for(
        leaky_server(), auth=BearerAuth(verifier), resource_metadata=METADATA
    )
    bad = make_token(aud="https://evil.example.com")
    with caplog.at_level(logging.DEBUG):
        result = handler(event(rpc("tools/list"), token=bad), None)
    assert result["statusCode"] == 401
    assert bad not in caplog.text
    assert bad not in str(result)
