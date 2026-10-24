"""OAuth 2.0 Protected Resource Metadata (RFC 9728) and `WWW-Authenticate` challenges."""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from typing import Final
from urllib.parse import urlsplit

__all__ = ["WELL_KNOWN", "ProtectedResourceMetadata", "challenge"]

WELL_KNOWN: Final = "/.well-known/oauth-protected-resource"

_SAFE_PARAM = re.compile(r"^[\x20\x21\x23-\x5B\x5D-\x7E]*$")  # quoted-string without " and \


def _check_url(url: str, what: str) -> str:
    parts = urlsplit(url)
    local = parts.hostname in ("localhost", "127.0.0.1", "::1")
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ValueError(f"{what} must be an absolute URL: {url!r}")
    if parts.scheme == "http" and not local:
        raise ValueError(f"{what} must use https (http only for localhost): {url!r}")
    if parts.fragment or "#" in url:
        raise ValueError(f"{what} must not contain a fragment: {url!r}")
    return url


@dataclass(frozen=True)
class ProtectedResourceMetadata:
    """The document MCP clients read to find the authorization server.

    `resource` is the MCP server's canonical URI (e.g.
    `https://mcp.example.com/mcp`): the value tokens must carry as their
    audience. Configure it explicitly; it is never derived from the request's
    `Host` header, which a client controls.
    """

    resource: str
    authorization_servers: tuple[str, ...]
    scopes_supported: tuple[str, ...] = ()
    resource_name: str | None = None
    resource_documentation: str | None = None

    def __post_init__(self) -> None:
        _check_url(self.resource, "resource")
        if not self.authorization_servers:
            raise ValueError("at least one authorization server is required")
        for server in self.authorization_servers:
            _check_url(server, "authorization server")
        if self.resource_documentation:
            _check_url(self.resource_documentation, "resource_documentation")
        if "offline_access" in self.scopes_supported:
            raise ValueError("offline_access is not a resource scope (MCP authorization spec)")

    @classmethod
    def create(
        cls,
        resource: str,
        authorization_servers: Iterable[str],
        scopes_supported: Iterable[str] = (),
        **kwargs: Any,
    ) -> ProtectedResourceMetadata:
        return cls(
            resource=resource.rstrip("/") if urlsplit(resource).path not in ("", "/") else resource,
            authorization_servers=tuple(authorization_servers),
            scopes_supported=tuple(scopes_supported),
            **kwargs,
        )

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> ProtectedResourceMetadata:
        """Build from `MCP_RESOURCE`, `MCP_AUTHORIZATION_SERVERS` and `MCP_SCOPES`."""
        env = os.environ if env is None else env
        try:
            resource = env["MCP_RESOURCE"]
            servers = env["MCP_AUTHORIZATION_SERVERS"]
        except KeyError as exc:
            raise ValueError(f"missing environment variable {exc.args[0]}") from None
        return cls.create(
            resource,
            [s.strip() for s in servers.split(",") if s.strip()],
            env.get("MCP_SCOPES", "").split(),
        )

    @property
    def resource_path(self) -> str:
        return urlsplit(self.resource).path.rstrip("/")

    @property
    def metadata_url(self) -> str:
        """The path-inserted well-known URL (RFC 9728 section 3.1)."""
        parts = urlsplit(self.resource)
        return f"{parts.scheme}://{parts.netloc}{WELL_KNOWN}{self.resource_path}"

    def paths(self) -> tuple[str, ...]:
        """Every path this document is served at: path-inserted first, then the root."""
        if self.resource_path:
            return (f"{WELL_KNOWN}{self.resource_path}", WELL_KNOWN)
        return (WELL_KNOWN,)

    def to_dict(self) -> dict[str, Any]:
        doc: dict[str, Any] = {
            "resource": self.resource,
            "authorization_servers": list(self.authorization_servers),
            "bearer_methods_supported": ["header"],
        }
        if self.scopes_supported:
            doc["scopes_supported"] = list(self.scopes_supported)
        if self.resource_name:
            doc["resource_name"] = self.resource_name
        if self.resource_documentation:
            doc["resource_documentation"] = self.resource_documentation
        return doc


def challenge(
    *,
    resource_metadata: str | None,
    error: str | None = None,
    description: str | None = None,
    scopes: Iterable[str] = (),
) -> str:
    """A `WWW-Authenticate: Bearer ...` value (RFC 6750 section 3).

    Values are fixed strings from this library; anything that is not a safe
    quoted-string is dropped rather than escaped.
    """
    params: list[tuple[str, str]] = []
    if error:
        params.append(("error", error))
    if description:
        params.append(("error_description", description))
    scope = " ".join(scopes)
    if scope:
        params.append(("scope", scope))
    if resource_metadata:
        params.append(("resource_metadata", resource_metadata))
    rendered = [f'{k}="{v}"' for k, v in params if _SAFE_PARAM.match(v)]
    return "Bearer " + ", ".join(rendered) if rendered else "Bearer"
