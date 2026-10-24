"""CDK app for the notes example. `cdk synth` only: this repository never deploys.

```bash
pip install -t build/notes "serverless-mcp-aws" && cp -r examples build/notes/
cdk synth --app "python examples/notes/infra.py"
```

Set the issuer/JWKS/resource values in `ENVIRONMENT` to your own
authorization server before you deploy anything to your own account.
"""

from __future__ import annotations

from aws_cdk import App
from aws_cdk import CfnOutput
from aws_cdk import RemovalPolicy
from aws_cdk import Stack
from aws_cdk import aws_lambda as lambda_
from aws_cdk import aws_s3 as s3
from constructs import Construct

from serverless_mcp_aws.cdk import LambdaAuthorizer
from serverless_mcp_aws.cdk import McpServerFunction

ENVIRONMENT = {
    "MCP_RESOURCE": "https://mcp.example.com/mcp",
    "MCP_AUTHORIZATION_SERVERS": "https://auth.example.com",
    "MCP_SCOPES": "notes:read notes:write",
    "MCP_JWT_ISSUER": "https://auth.example.com",
    "MCP_JWT_JWKS_URL": "https://auth.example.com/.well-known/jwks.json",
}


class NotesStack(Stack):
    def __init__(
        self,
        scope: Construct,
        id: str,
        *,
        code: lambda_.Code,
        use_lambda_authorizer: bool = False,
    ) -> None:
        super().__init__(scope, id)
        bucket = s3.Bucket(
            self,
            "Notes",
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            versioned=False,
            removal_policy=RemovalPolicy.DESTROY,
        )
        authorizer = (
            LambdaAuthorizer(
                code=code,
                handler="examples.notes.authorizer.handler",
                environment=ENVIRONMENT,
            )
            if use_lambda_authorizer
            else None
        )
        mcp = McpServerFunction(
            self,
            "Mcp",
            code=code,
            handler="examples.notes.app.handler",
            environment={
                **ENVIRONMENT,
                "NOTES_BUCKET": bucket.bucket_name,
                "NOTES_AUTH": "authorizer" if use_lambda_authorizer else "bearer",
            },
            authorizer=authorizer,
        )
        # Only the notes/ prefix, read and write: nothing else in the account.
        bucket.grant_read_write(mcp.function, "notes/*")
        CfnOutput(self, "McpEndpoint", value=mcp.endpoint)


if __name__ == "__main__":
    app = App()
    NotesStack(app, "ServerlessMcpNotes", code=lambda_.Code.from_asset("build/notes"))
    app.synth()
