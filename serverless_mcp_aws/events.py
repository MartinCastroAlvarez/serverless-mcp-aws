"""API Gateway HTTP API (payload format 2.0) events in, Lambda proxy responses out.

Only the fields this library reads are parsed. Header names are lower-cased
(API Gateway already does this; the local dev server does it too) and a
repeated header arrives comma-joined, exactly as API Gateway delivers it.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field
from typing import Any
from urllib.parse import parse_qs

__all__ = ["BadEvent", "BodyTooLarge", "HttpRequest", "HttpResponse", "json_response"]


class BadEvent(ValueError):
    """The Lambda event is not an API Gateway HTTP API v2.0 proxy event."""


@dataclass(frozen=True)
class HttpRequest:
    """One HTTP request, as delivered by API Gateway (or the local dev server)."""

    method: str
    path: str
    headers: Mapping[str, str]
    body: bytes
    query: Mapping[str, list[str]] = field(default_factory=dict)
    source_ip: str = ""
    request_id: str = ""
    authorizer: Mapping[str, Any] = field(default_factory=dict)
    """`requestContext.authorizer` as API Gateway set it (never client-controlled)."""

    def header(self, name: str) -> str | None:
        return self.headers.get(name.lower())

    @classmethod
    def from_event(cls, event: Mapping[str, Any], *, max_body_bytes: int) -> HttpRequest:
        """Parse a payload-format-2.0 event; refuse anything else.

        Raises `BadEvent` for a malformed event and `BodyTooLarge` when the
        decoded body is larger than `max_body_bytes`.
        """
        if not isinstance(event, Mapping) or event.get("version") != "2.0":
            raise BadEvent("expected an API Gateway HTTP API payload format 2.0 event")
        ctx = event.get("requestContext")
        if not isinstance(ctx, Mapping):
            raise BadEvent("missing requestContext")
        http = ctx.get("http")
        if not isinstance(http, Mapping):
            raise BadEvent("missing requestContext.http")
        method = http.get("method")
        path = event.get("rawPath", http.get("path"))
        if not isinstance(method, str) or not isinstance(path, str):
            raise BadEvent("missing method or path")

        raw_headers = event.get("headers") or {}
        if not isinstance(raw_headers, Mapping):
            raise BadEvent("headers must be an object")
        headers: dict[str, str] = {}
        for key, value in raw_headers.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise BadEvent("header names and values must be strings")
            headers[key.lower()] = value

        raw_body = event.get("body")
        body: bytes
        if raw_body is None:
            body = b""
        elif not isinstance(raw_body, str):
            raise BadEvent("body must be a string")
        elif event.get("isBase64Encoded"):
            # Base64 inflates by 4/3: refuse before decoding something huge.
            if len(raw_body) > (max_body_bytes * 4) // 3 + 4:
                raise BodyTooLarge
            try:
                body = base64.b64decode(raw_body, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise BadEvent("body is not valid base64") from exc
        else:
            body = raw_body.encode("utf-8")
        if len(body) > max_body_bytes:
            raise BodyTooLarge

        raw_query = event.get("rawQueryString") or ""
        query = parse_qs(raw_query, keep_blank_values=True) if isinstance(raw_query, str) else {}

        authorizer = ctx.get("authorizer")
        return cls(
            method=method.upper(),
            path=path,
            headers=headers,
            body=body,
            query=query,
            source_ip=str(http.get("sourceIp", "")),
            request_id=str(ctx.get("requestId", "")),
            authorizer=authorizer if isinstance(authorizer, Mapping) else {},
        )


class BodyTooLarge(Exception):
    """The request body is larger than the configured limit."""


@dataclass
class HttpResponse:
    """A Lambda proxy response for API Gateway."""

    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    def to_lambda(self) -> dict[str, Any]:
        try:
            text = self.body.decode("utf-8")
        except UnicodeDecodeError:
            return {
                "statusCode": self.status,
                "headers": dict(self.headers),
                "body": base64.b64encode(self.body).decode("ascii"),
                "isBase64Encoded": True,
            }
        return {
            "statusCode": self.status,
            "headers": dict(self.headers),
            "body": text,
            "isBase64Encoded": False,
        }


def json_response(
    status: int, payload: Any, headers: Mapping[str, str] | None = None
) -> HttpResponse:
    """A compact JSON response."""
    out = {"content-type": "application/json"}
    out.update(headers or {})
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return HttpResponse(status=status, headers=out, body=body)
