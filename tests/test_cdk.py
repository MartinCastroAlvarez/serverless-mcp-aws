"""The CDK construct, checked with CDK assertions on the synthesised template.

`cdk synth` only: nothing here talks to AWS.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

cdk = pytest.importorskip("aws_cdk")

from aws_cdk import App
from aws_cdk import Duration
from aws_cdk import Stack
from aws_cdk import aws_lambda as lambda_
from aws_cdk.assertions import Match
from aws_cdk.assertions import Template

from examples.notes.infra import NotesStack
from serverless_mcp_aws.cdk import JwtAuthorizer
from serverless_mcp_aws.cdk import LambdaAuthorizer
from serverless_mcp_aws.cdk import McpServerFunction

pytestmark = pytest.mark.cdk

CODE = "def handler(event, context):\n    return {}\n"


def synth(**kwargs: Any) -> tuple[Template, McpServerFunction]:
    app = App()
    stack = Stack(app, "Test")
    construct = McpServerFunction(
        stack,
        "Mcp",
        code=lambda_.Code.from_inline(CODE),
        handler="index.handler",
        environment={"MCP_RESOURCE": "https://mcp.example.com/mcp"},
        **kwargs,
    )
    return Template.from_stack(stack), construct


@pytest.fixture(scope="module")
def plain() -> Template:
    return synth()[0]


@pytest.fixture(scope="module")
def with_lambda_authorizer() -> Template:
    return synth(
        authorizer=LambdaAuthorizer(code=lambda_.Code.from_inline(CODE), handler="index.handler")
    )[0]


def test_function(plain: Template) -> None:
    plain.resource_count_is("AWS::Lambda::Function", 1)
    plain.has_resource_properties(
        "AWS::Lambda::Function",
        {
            "Runtime": "python3.12",
            "Architectures": ["arm64"],
            "MemorySize": 512,
            "Timeout": 29,
            "Handler": "index.handler",
            "Environment": {"Variables": {"MCP_RESOURCE": "https://mcp.example.com/mcp"}},
            "LoggingConfig": {"LogGroup": Match.any_value()},
        },
    )


def test_log_retention_is_one_day(plain: Template, with_lambda_authorizer: Template) -> None:
    plain.has_resource_properties("AWS::Logs::LogGroup", {"RetentionInDays": 1})
    groups = with_lambda_authorizer.find_resources("AWS::Logs::LogGroup")
    assert len(groups) == 2
    assert all(g["Properties"]["RetentionInDays"] == 1 for g in groups.values())
    assert not plain.find_resources("Custom::LogRetention")


def _statements(template: Template) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for policy in template.find_resources("AWS::IAM::Policy").values():
        out.extend(policy["Properties"]["PolicyDocument"]["Statement"])
    return out


def test_least_privilege_iam(plain: Template, with_lambda_authorizer: Template) -> None:
    for template in (plain, with_lambda_authorizer):
        for role in template.find_resources("AWS::IAM::Role").values():
            assert "ManagedPolicyArns" not in role["Properties"]  # no AWSLambdaBasicExecutionRole
        for stmt in _statements(template):
            assert stmt["Effect"] == "Allow"
            assert sorted(stmt["Action"]) == ["logs:CreateLogStream", "logs:PutLogEvents"]
            assert stmt["Resource"] != "*"
            assert "Fn::GetAtt" in stmt["Resource"]
        assert "logs:CreateLogGroup" not in json.dumps(template.to_json())
        assert '"*"' not in json.dumps(_statements(template))


def test_api_stage_is_throttled(plain: Template) -> None:
    plain.resource_count_is("AWS::ApiGatewayV2::Api", 1)
    plain.has_resource_properties(
        "AWS::ApiGatewayV2::Api", {"ProtocolType": "HTTP", "DisableExecuteApiEndpoint": False}
    )
    plain.has_resource_properties(
        "AWS::ApiGatewayV2::Stage",
        {
            "StageName": "$default",
            "AutoDeploy": True,
            "DefaultRouteSettings": {"ThrottlingRateLimit": 10, "ThrottlingBurstLimit": 20},
        },
    )


def _routes(template: Template) -> dict[str, dict[str, Any]]:
    return {
        r["Properties"]["RouteKey"]: r["Properties"]
        for r in template.find_resources("AWS::ApiGatewayV2::Route").values()
    }


def test_routes_without_authorizer(plain: Template) -> None:
    routes = _routes(plain)
    assert set(routes) == {
        "ANY /mcp",
        "OPTIONS /mcp",
        "GET /.well-known/oauth-protected-resource/mcp",
        "GET /.well-known/oauth-protected-resource",
    }
    assert all(r.get("AuthorizationType", "NONE") == "NONE" for r in routes.values())
    plain.resource_count_is("AWS::ApiGatewayV2::Authorizer", 0)


def test_lambda_authorizer(with_lambda_authorizer: Template) -> None:
    t = with_lambda_authorizer
    t.resource_count_is("AWS::Lambda::Function", 2)
    t.has_resource_properties(
        "AWS::ApiGatewayV2::Authorizer",
        {
            "AuthorizerType": "REQUEST",
            "AuthorizerPayloadFormatVersion": "2.0",
            "EnableSimpleResponses": True,
            "AuthorizerResultTtlInSeconds": 0,
            "IdentitySource": ["$request.header.Authorization"],
        },
    )
    routes = _routes(t)
    assert routes["ANY /mcp"]["AuthorizationType"] == "CUSTOM"
    for key in (
        "OPTIONS /mcp",
        "GET /.well-known/oauth-protected-resource/mcp",
        "GET /.well-known/oauth-protected-resource",
    ):
        assert routes[key]["AuthorizationType"] == "NONE", key
    # API Gateway may invoke both functions; nothing else is granted.
    perms = t.find_resources("AWS::Lambda::Permission")
    assert perms
    assert all(p["Properties"]["Principal"] == "apigateway.amazonaws.com" for p in perms.values())


def test_jwt_authorizer() -> None:
    template, _ = synth(
        authorizer=JwtAuthorizer(
            issuer="https://auth.example.com", audience=["https://mcp.example.com/mcp"]
        )
    )
    template.has_resource_properties(
        "AWS::ApiGatewayV2::Authorizer",
        {
            "AuthorizerType": "JWT",
            "JwtConfiguration": {
                "Issuer": "https://auth.example.com",
                "Audience": ["https://mcp.example.com/mcp"],
            },
        },
    )
    assert _routes(template)["ANY /mcp"]["AuthorizationType"] == "JWT"


def test_options() -> None:
    template, construct = synth(
        mcp_path="/tools/mcp",
        memory_size=1024,
        timeout=Duration.seconds(10),
        reserved_concurrent_executions=5,
        throttle_rate_limit=2,
        throttle_burst_limit=4,
        disable_execute_api_endpoint=True,
    )
    assert "GET /.well-known/oauth-protected-resource/tools/mcp" in _routes(template)
    template.has_resource_properties(
        "AWS::Lambda::Function",
        {"MemorySize": 1024, "Timeout": 10, "ReservedConcurrentExecutions": 5},
    )
    template.has_resource_properties(
        "AWS::ApiGatewayV2::Stage",
        {"DefaultRouteSettings": {"ThrottlingRateLimit": 2, "ThrottlingBurstLimit": 4}},
    )
    with pytest.raises(ValueError, match="custom domain"):
        _ = construct.endpoint
    template.has_resource_properties("AWS::ApiGatewayV2::Api", {"DisableExecuteApiEndpoint": True})


def test_endpoint_url() -> None:
    _, construct = synth(mcp_path="/tools/mcp")
    assert construct.endpoint.endswith("/tools/mcp")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"mcp_path": "mcp"},
        {"mcp_path": "/mcp/"},
        {"mcp_path": "/.well-known/oauth-protected-resource"},
        {"throttle_rate_limit": 0},
        {"authorizer": JwtAuthorizer(issuer="https://a.example.com", audience=[])},
        {"authorizer": "lambda"},
    ],
)
def test_bad_options(kwargs: dict[str, Any]) -> None:
    with pytest.raises((ValueError, TypeError)):
        synth(**kwargs)


@pytest.mark.parametrize("use_lambda_authorizer", [False, True])
def test_notes_example_stack(use_lambda_authorizer: bool) -> None:
    app = App()
    stack = NotesStack(
        app,
        "Notes",
        code=lambda_.Code.from_inline(CODE),
        use_lambda_authorizer=use_lambda_authorizer,
    )
    t = Template.from_stack(stack)
    t.has_resource_properties(
        "AWS::S3::Bucket",
        {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "BlockPublicPolicy": True,
                "IgnorePublicAcls": True,
                "RestrictPublicBuckets": True,
            },
            "BucketEncryption": Match.any_value(),
        },
    )
    # S3 access is scoped to this bucket and its notes/ prefix.
    s3_statements = [
        s for s in _statements(t) if any(str(a).startswith("s3:") for a in s["Action"])
    ]
    assert len(s3_statements) == 1
    resources = json.dumps(s3_statements[0]["Resource"])
    assert "/notes/*" in resources and '"*"' not in resources
    t.has_resource_properties(
        "AWS::Lambda::Function",
        {
            "Environment": {
                "Variables": Match.object_like(
                    {"NOTES_AUTH": "authorizer" if use_lambda_authorizer else "bearer"}
                )
            }
        },
    )
    t.has_output("McpEndpoint", {})
