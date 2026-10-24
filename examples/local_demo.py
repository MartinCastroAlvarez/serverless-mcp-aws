"""The whole stack on localhost: no AWS, no identity provider, no paid API.

* a throwaway RSA key and a JWKS endpoint on 127.0.0.1 play the authorization server,
* moto plays S3 for the notes example,
* the dev server runs the same Lambda handler API Gateway would invoke,
* the official MCP client talks to it with two different tokens.

    python examples/local_demo.py
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer
from typing import Any

import boto3
import httpx2
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from moto import mock_aws

from serverless_mcp_aws.dev import DevServer

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def serve_jwks() -> HTTPServer:
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key()))
    body = json.dumps({"keys": [{**jwk, "kid": "demo", "alg": "RS256", "use": "sig"}]}).encode()

    class Jwks(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            pass

        def do_GET(self) -> None:
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = HTTPServer(("127.0.0.1", 0), Jwks)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def mint(issuer: str, resource: str, sub: str, scope: str) -> str:
    now = int(time.time())
    claims = {
        "iss": issuer,
        "aud": resource,
        "sub": sub,
        "scope": scope,
        "iat": now,
        "exp": now + 300,
    }
    return jwt.encode(claims, KEY, algorithm="RS256", headers={"kid": "demo", "typ": "at+jwt"})


async def as_user(url: str, token: str, title: str | None) -> dict[str, Any]:
    headers = {"authorization": f"Bearer {token}"}
    async with (
        httpx2.AsyncClient(headers=headers) as http,
        Client(streamable_http_client(url, http_client=http)) as client,
    ):
        tools = sorted(t.name for t in (await client.list_tools()).tools)
        if title:
            await client.call_tool("add_note", {"title": title, "body": "from the demo"})
        notes = await client.call_tool("list_notes", {})
        return {
            "protocol": client.protocol_version,
            "tools": tools,
            "notes": notes.structured_content,
        }


def main() -> None:
    jwks = serve_jwks()
    issuer = f"http://127.0.0.1:{jwks.server_address[1]}"
    os.environ.update(
        {
            "AWS_ACCESS_KEY_ID": "testing",
            "AWS_SECRET_ACCESS_KEY": "testing",
            "AWS_DEFAULT_REGION": "us-east-1",
            "NOTES_BUCKET": "demo-notes",
            "MCP_AUTHORIZATION_SERVERS": issuer,
            "MCP_SCOPES": "notes:read notes:write",
            "MCP_JWT_ISSUER": issuer,
            "MCP_JWT_JWKS_URL": f"{issuer}/jwks.json",
        }
    )
    with mock_aws():
        boto3.client("s3").create_bucket(Bucket="demo-notes")
        from examples.notes.app import build_handler

        # The resource URI must be the address clients use: pick the port first.
        dev = DevServer(lambda e, c: handler(e, c), port=0)
        resource = f"{dev.url.replace('127.0.0.1', 'localhost')}/mcp"
        os.environ["MCP_RESOURCE"] = resource
        handler = build_handler()
        with dev:
            url = f"{dev.url}/mcp"
            alice = mint(issuer, resource, "alice", "notes:write")
            bob = mint(issuer, resource, "bob", "notes:read")
            print("alice (notes:write):", asyncio.run(as_user(url, alice, "Buy milk")))
            print("bob   (notes:read): ", asyncio.run(as_user(url, bob, None)))
            stranger = mint(issuer, "https://other.example.com/mcp", "eve", "notes:write")
            req = httpx2.post(url, headers={"authorization": f"Bearer {stranger}"}, json={})
            print(
                "eve (token for another server):", req.status_code, req.headers["www-authenticate"]
            )
    jwks.shutdown()


if __name__ == "__main__":
    main()
