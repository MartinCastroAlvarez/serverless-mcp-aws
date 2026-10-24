"""Scopes to tools: which tools a token may list and call."""

from __future__ import annotations

import re
from collections.abc import Iterable
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from serverless_mcp_aws.auth.principal import Principal

__all__ = ["ALL_TOOLS", "ToolPolicy"]

ALL_TOOLS: Final = "*"
"""Grants every tool (for an admin scope)."""

_SCOPE_TOKEN = re.compile(r"^[\x21\x23-\x5B\x5D-\x7E]+$")  # RFC 6749 scope-token


@dataclass(frozen=True)
class ToolPolicy:
    """A map from OAuth scope to the tools it grants. Default deny.

    ```python
    ToolPolicy({"notes:read": ["list_notes", "read_note"],
                "notes:write": ["add_note", "list_notes", "read_note"],
                "notes:admin": ["*"]})
    ```

    A broader scope implies narrower ones simply by listing their tools too.
    A tool that no scope grants is never callable and never listed.
    """

    grants: Mapping[str, frozenset[str]]

    def __init__(self, grants: Mapping[str, Iterable[str]]) -> None:
        cleaned: dict[str, frozenset[str]] = {}
        for scope, tools in grants.items():
            if not _SCOPE_TOKEN.match(scope):
                raise ValueError(f"invalid scope token: {scope!r}")
            if isinstance(tools, str):
                raise TypeError(f"tools for scope {scope!r} must be a list, not a string")
            cleaned[scope] = frozenset(tools)
        object.__setattr__(self, "grants", cleaned)

    @property
    def scopes(self) -> tuple[str, ...]:
        return tuple(sorted(self.grants))

    def allowed_tools(self, principal: Principal) -> frozenset[str] | None:
        """The tools `principal` may use; `None` means all of them."""
        allowed: set[str] = set()
        for scope in principal.scopes:
            tools = self.grants.get(scope)
            if tools is None:
                continue
            if ALL_TOOLS in tools:
                return None
            allowed |= tools
        return frozenset(allowed)

    def allows(self, principal: Principal, tool: str) -> bool:
        allowed = self.allowed_tools(principal)
        return allowed is None or tool in allowed

    def scopes_for(self, tool: str) -> tuple[str, ...]:
        """Scopes that would grant `tool` (for the `insufficient_scope` challenge)."""
        return tuple(
            sorted(s for s, tools in self.grants.items() if tool in tools or ALL_TOOLS in tools)
        )
