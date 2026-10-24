"""Authentication and authorization: JWT verification, principals, scope policy, metadata."""

from serverless_mcp_aws.auth.authenticators import Authenticator
from serverless_mcp_aws.auth.authenticators import AuthError
from serverless_mcp_aws.auth.authenticators import AuthorizerContextAuth
from serverless_mcp_aws.auth.authenticators import BearerAuth
from serverless_mcp_aws.auth.jwt import SAFE_ALGORITHMS
from serverless_mcp_aws.auth.jwt import InvalidToken
from serverless_mcp_aws.auth.jwt import JWKSCache
from serverless_mcp_aws.auth.jwt import JWTVerifier
from serverless_mcp_aws.auth.metadata import ProtectedResourceMetadata
from serverless_mcp_aws.auth.policy import ALL_TOOLS
from serverless_mcp_aws.auth.policy import ToolPolicy
from serverless_mcp_aws.auth.principal import ANONYMOUS
from serverless_mcp_aws.auth.principal import Principal
from serverless_mcp_aws.auth.principal import current_principal
from serverless_mcp_aws.auth.principal import principal_scope

__all__ = [
    "ALL_TOOLS",
    "ANONYMOUS",
    "SAFE_ALGORITHMS",
    "AuthError",
    "Authenticator",
    "AuthorizerContextAuth",
    "BearerAuth",
    "InvalidToken",
    "JWKSCache",
    "JWTVerifier",
    "Principal",
    "ProtectedResourceMetadata",
    "ToolPolicy",
    "current_principal",
    "principal_scope",
]
