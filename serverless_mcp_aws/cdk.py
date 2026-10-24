"""AWS CDK construct: an MCP server as Lambda + API Gateway HTTP API.

Requires the `cdk` extra (`pip install "serverless-mcp-aws[cdk]"`) and Node.js
(CDK synthesises through jsii). This library only ever *synthesises* it in its
tests; deploying is your call and your account.

```python
from aws_cdk import aws_lambda as lambda_
from serverless_mcp_aws.cdk import LambdaAuthorizer, McpServerFunction

mcp = McpServerFunction(
    self, "Notes",
    code=lambda_.Code.from_asset("build/notes"),
    handler="examples.notes.app.handler",
    environment={"MCP_RESOURCE": "https://mcp.example.com/mcp", ...},
)
bucket.grant_read_write(mcp.function, "notes/*")
```

What it builds, least privilege by default:

* the MCP function, ARM64, with its own IAM role whose only permissions are
  `logs:CreateLogStream` / `logs:PutLogEvents` on its own log group (no
  `AWSLambdaBasicExecutionRole`, no `*` resources); grant it more explicitly;
* log groups with 1-day retention, created up front (no `logs:CreateLogGroup`);
* an HTTP API with a `$default` stage throttled to `throttle_rate_limit`
  requests/second (burst `throttle_burst_limit`);
* routes: `ANY <mcp_path>` (behind the authorizer, if any), `OPTIONS
  <mcp_path>` (CORS preflight, public) and `GET` on both protected resource
  metadata paths (public, as RFC 9728 requires);
* optionally a Lambda REQUEST authorizer (simple responses, results cache off
  by default) or API Gateway's native JWT authorizer.
"""

from __future__ import annotations

from collections.abc import Mapping
from collections.abc import Sequence
from dataclasses import dataclass
from dataclasses import field

from aws_cdk import Duration
from aws_cdk import RemovalPolicy
from aws_cdk import aws_apigatewayv2 as apigw
from aws_cdk import aws_apigatewayv2_authorizers as authorizers
from aws_cdk import aws_apigatewayv2_integrations as integrations
from aws_cdk import aws_iam as iam
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_logs as logs
from constructs import Construct

__all__ = ["JwtAuthorizer", "LambdaAuthorizer", "McpServerFunction"]

WELL_KNOWN = "/.well-known/oauth-protected-resource"


@dataclass(frozen=True)
class LambdaAuthorizer:
    """A REQUEST authorizer function (see `serverless_mcp_aws.authorizer_handler_for`).

    Pair it with `AuthorizerContextAuth()` in the MCP function.
    `results_cache_ttl` defaults to zero: a cached decision could outlive the
    token (the handler re-checks `exp` either way).
    """

    code: lambda_.Code
    handler: str
    environment: Mapping[str, str] = field(default_factory=dict)
    results_cache_ttl: Duration | None = None
    memory_size: int = 256
    timeout: Duration | None = None


@dataclass(frozen=True)
class JwtAuthorizer:
    """API Gateway's built-in JWT authorizer.

    Pair it with `AuthorizerContextAuth("jwt")`. API Gateway checks the
    signature (RSA keys from the issuer's JWKS), `iss`, `aud`, `exp` and `nbf`.
    """

    issuer: str
    audience: Sequence[str]


def _log_group(scope: Construct, id: str, retention: logs.RetentionDays) -> logs.LogGroup:
    return logs.LogGroup(scope, id, retention=retention, removal_policy=RemovalPolicy.DESTROY)


def _role(scope: Construct, id: str, log_group: logs.ILogGroup) -> iam.Role:
    role = iam.Role(
        scope,
        id,
        assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
        description="Least privilege: writes to its own log group only",
    )
    role.add_to_policy(
        iam.PolicyStatement(
            actions=["logs:CreateLogStream", "logs:PutLogEvents"],
            resources=[log_group.log_group_arn],
        )
    )
    return role


class McpServerFunction(Construct):
    """An MCP server on Lambda behind an API Gateway HTTP API."""

    def __init__(
        self,
        scope: Construct,
        id: str,
        *,
        code: lambda_.Code,
        handler: str,
        environment: Mapping[str, str] | None = None,
        authorizer: LambdaAuthorizer | JwtAuthorizer | None = None,
        mcp_path: str = "/mcp",
        runtime: lambda_.Runtime | None = None,
        architecture: lambda_.Architecture | None = None,
        memory_size: int = 512,
        timeout: Duration | None = None,
        reserved_concurrent_executions: int | None = None,
        throttle_rate_limit: float = 10,
        throttle_burst_limit: int = 20,
        log_retention: logs.RetentionDays = logs.RetentionDays.ONE_DAY,
        api_name: str | None = None,
        disable_execute_api_endpoint: bool = False,
    ) -> None:
        super().__init__(scope, id)
        if (
            not mcp_path.startswith("/")
            or mcp_path.endswith("/")
            or mcp_path.startswith(WELL_KNOWN)
        ):
            raise ValueError("mcp_path must look like /mcp")
        if throttle_rate_limit <= 0 or throttle_burst_limit <= 0:
            raise ValueError("throttling must be enabled (positive rate and burst limits)")
        self.mcp_path = mcp_path
        self._execute_api_disabled = disable_execute_api_endpoint

        self.log_group = _log_group(self, "Logs", log_retention)
        self.role = _role(self, "Role", self.log_group)
        self.function = lambda_.Function(
            self,
            "Function",
            code=code,
            handler=handler,
            runtime=runtime or lambda_.Runtime.PYTHON_3_12,
            architecture=architecture or lambda_.Architecture.ARM_64,
            memory_size=memory_size,
            # API Gateway HTTP APIs give up after 30 seconds.
            timeout=timeout or Duration.seconds(29),
            environment=dict(environment or {}),
            role=self.role,
            log_group=self.log_group,
            reserved_concurrent_executions=reserved_concurrent_executions,
            description="MCP server (stateless Streamable HTTP)",
        )

        self.authorizer_function: lambda_.Function | None = None
        route_authorizer: apigw.IHttpRouteAuthorizer | None = None
        if isinstance(authorizer, LambdaAuthorizer):
            auth_logs = _log_group(self, "AuthorizerLogs", log_retention)
            self.authorizer_function = lambda_.Function(
                self,
                "AuthorizerFunction",
                code=authorizer.code,
                handler=authorizer.handler,
                runtime=runtime or lambda_.Runtime.PYTHON_3_12,
                architecture=architecture or lambda_.Architecture.ARM_64,
                memory_size=authorizer.memory_size,
                timeout=authorizer.timeout or Duration.seconds(5),
                environment=dict(authorizer.environment),
                role=_role(self, "AuthorizerRole", auth_logs),
                log_group=auth_logs,
                description="MCP bearer-token authorizer",
            )
            route_authorizer = authorizers.HttpLambdaAuthorizer(
                "Authorizer",
                self.authorizer_function,
                response_types=[authorizers.HttpLambdaResponseType.SIMPLE],
                identity_source=["$request.header.Authorization"],
                results_cache_ttl=authorizer.results_cache_ttl or Duration.seconds(0),
            )
        elif isinstance(authorizer, JwtAuthorizer):
            if not authorizer.audience:
                raise ValueError("JwtAuthorizer needs an audience (the MCP resource URI)")
            route_authorizer = authorizers.HttpJwtAuthorizer(
                "Authorizer",
                authorizer.issuer,
                jwt_audience=list(authorizer.audience),
                identity_source=["$request.header.Authorization"],
            )
        elif authorizer is not None:
            raise TypeError("authorizer must be a LambdaAuthorizer, a JwtAuthorizer or None")

        self.api = apigw.HttpApi(
            self,
            "Api",
            api_name=api_name,
            create_default_stage=False,
            disable_execute_api_endpoint=disable_execute_api_endpoint,
            description="MCP server",
        )
        self.stage = apigw.HttpStage(
            self,
            "Stage",
            http_api=self.api,
            stage_name="$default",
            auto_deploy=True,
            throttle=apigw.ThrottleSettings(
                rate_limit=throttle_rate_limit, burst_limit=throttle_burst_limit
            ),
        )
        integration = integrations.HttpLambdaIntegration("Integration", self.function)

        def route(rid: str, method: apigw.HttpMethod, path: str, protected: bool) -> None:
            apigw.HttpRoute(
                self,
                rid,
                http_api=self.api,
                route_key=apigw.HttpRouteKey.with_(path, method),
                integration=integration,
                authorizer=route_authorizer if protected else apigw.HttpNoneAuthorizer(),
            )

        route("McpRoute", apigw.HttpMethod.ANY, mcp_path, protected=True)
        route("McpPreflightRoute", apigw.HttpMethod.OPTIONS, mcp_path, protected=False)
        route("MetadataRoute", apigw.HttpMethod.GET, f"{WELL_KNOWN}{mcp_path}", protected=False)
        route("RootMetadataRoute", apigw.HttpMethod.GET, WELL_KNOWN, protected=False)

    @property
    def endpoint(self) -> str:
        """The MCP endpoint URL on the execute-api domain (a deploy-time token)."""
        if self._execute_api_disabled:
            raise ValueError("the execute-api endpoint is disabled: use your custom domain")
        return f"{self.api.api_endpoint}{self.mcp_path}"
