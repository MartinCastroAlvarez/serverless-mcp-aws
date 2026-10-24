# Examples

| File | What |
| --- | --- |
| [`local_demo.py`](local_demo.py) | everything on localhost: a throwaway RSA key + JWKS server as the authorization server, moto as S3, the dev server running the Lambda handler, the official MCP client with a writer token, a reader token and a token for another server (`python -m examples.local_demo`) |
| [`notes/app.py`](notes/app.py) | the notes MCP server (`add_note`, `list_notes`, `read_note`) on S3, per-caller key prefixes, scope-based tool allowlist; Lambda entry point `examples.notes.app.handler` |
| [`notes/authorizer.py`](notes/authorizer.py) | the same token checks as a Lambda REQUEST authorizer |
| [`notes/infra.py`](notes/infra.py) | CDK app: private encrypted bucket + `McpServerFunction`, S3 access limited to `notes/*` (`cdk synth` only) |

Run the notes server locally without auth against your own local S3 endpoint
(SeaweedFS, LocalStack community or moto server):

```bash
NOTES_BUCKET=notes AWS_ENDPOINT_URL=http://localhost:8333 \
  serverless-mcp-aws dev examples.notes.app:server
claude mcp add --transport http notes http://localhost:8000/mcp
```
