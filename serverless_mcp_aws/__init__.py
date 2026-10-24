"""Run an MCP server on AWS Lambda behind API Gateway (HTTP API).

```python
from mcp.server.mcpserver import MCPServer
from serverless_mcp_aws import BearerAuth, JWTVerifier, ProtectedResourceMetadata
from serverless_mcp_aws import lambda_handler_for

server = MCPServer("notes")
handler = lambda_handler_for(
    server,
    auth=BearerAuth(JWTVerifier.from_env()),
    resource_metadata=ProtectedResourceMetadata.from_env(),
)
```
"""

from serverless_mcp_aws.auth import ALL_TOOLS
from serverless_mcp_aws.auth import ANONYMOUS
from serverless_mcp_aws.auth import Authenticator
from serverless_mcp_aws.auth import AuthError
from serverless_mcp_aws.auth import AuthorizerContextAuth
from serverless_mcp_aws.auth import BearerAuth
from serverless_mcp_aws.auth import InvalidToken
from serverless_mcp_aws.auth import JWKSCache
from serverless_mcp_aws.auth import JWTVerifier
from serverless_mcp_aws.auth import Principal
from serverless_mcp_aws.auth import ProtectedResourceMetadata
from serverless_mcp_aws.auth import ToolPolicy
from serverless_mcp_aws.auth import current_principal
from serverless_mcp_aws.auth import principal_scope
from serverless_mcp_aws.authorizer import authorizer_handler_for
from serverless_mcp_aws.handler import McpLambdaHandler
from serverless_mcp_aws.handler import lambda_handler_for
from serverless_mcp_aws.origin import LOCAL_ORIGINS
from serverless_mcp_aws.origin import OriginPolicy

__version__ = "0.1.0"

__all__ = [
    "ALL_TOOLS",
    "ANONYMOUS",
    "LOCAL_ORIGINS",
    "AuthError",
    "Authenticator",
    "AuthorizerContextAuth",
    "BearerAuth",
    "InvalidToken",
    "JWKSCache",
    "JWTVerifier",
    "McpLambdaHandler",
    "OriginPolicy",
    "Principal",
    "ProtectedResourceMetadata",
    "ToolPolicy",
    "__version__",
    "authorizer_handler_for",
    "current_principal",
    "lambda_handler_for",
    "principal_scope",
]
