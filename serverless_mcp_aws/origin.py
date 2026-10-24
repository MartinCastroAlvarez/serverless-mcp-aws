"""Origin validation (DNS rebinding / cross-site request protection).

The Streamable HTTP spec: servers MUST validate the `Origin` header on every
incoming connection, and answer 403 when it is present and invalid. Requests
without an `Origin` header come from non-browser clients (MCP SDKs, curl,
agents) and are allowed: a browser always sends `Origin` on a cross-origin
POST, so a page on another site cannot omit it.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final

__all__ = ["LOCAL_ORIGINS", "OriginPolicy"]

LOCAL_ORIGINS: Final = ("http://localhost:*", "http://127.0.0.1:*", "http://[::1]:*")
"""Loopback origins on any port: what the local dev server allows."""

_ORIGIN = re.compile(r"^(https?)://([a-z0-9.-]+|\[[0-9a-f:]+\])(?::(\d{1,5}|\*))?$")


@dataclass(frozen=True)
class OriginPolicy:
    """An exact allowlist of browser origins (`scheme://host[:port]`).

    `http://localhost:*` matches any port. There is deliberately no `*`
    wildcard for hosts: a server that wants to be called from any web page
    should say so by listing them.
    """

    allowed: frozenset[str] = frozenset()

    @classmethod
    def of(cls, origins: Iterable[str]) -> OriginPolicy:
        cleaned: set[str] = set()
        for origin in origins:
            value = origin.strip().lower().rstrip("/")
            if not _ORIGIN.match(value):
                raise ValueError(f"not an origin (scheme://host[:port]): {origin!r}")
            cleaned.add(value)
        return cls(frozenset(cleaned))

    def allows(self, origin: str | None) -> bool:
        """True when the request may proceed. `None` means no Origin header."""
        if origin is None:
            return True
        value = origin.strip().lower()
        if value == "null" or not _ORIGIN.match(value) or value.endswith(":*"):
            return False
        if value in self.allowed:
            return True
        scheme_host, sep, _port = value.rpartition(":")
        if sep and _port.isdigit() and not scheme_host.endswith("/"):
            return f"{scheme_host}:*" in self.allowed
        return False
