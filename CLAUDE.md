# CLAUDE.md

Contract between this repository and any AI agent contributing to it.

## Required reading

1. This file. 2. [`README.md`](README.md). 3. [`ARCHITECTURE.md`](ARCHITECTURE.md).
4. [`SECURITY.md`](SECURITY.md).

## Mission

`serverless-mcp-aws` runs MCP servers on AWS Lambda behind API Gateway:
stateless, authenticated by default, least privilege, and testable offline.

## The rules

1. **The SDK owns the protocol.** Don't re-implement MCP message handling;
   adapt events, enforce policy, and let `mcp` dispatch.
2. **The token stops at the handler.** Tools get a `Principal`; never pass the
   bearer token, `Authorization` or cookies to tool code or other services.
3. **JWT rules are not configurable away**: RS256/ES256 only, keys only from the
   JWKS URL, `exp`/`iss`/`aud`/`sub` required, audience = the resource URI.
4. **Nothing stateful** between invocations; no sessions, no streams.
5. **Never deploy.** CDK code is tested with `aws_cdk.assertions` only; tests use
   moto, local keys and loopback servers. Never AWS, never a real IdP.
6. Every behaviour change gets an event-level test (and a hostile case when it
   touches security), plus README and CHANGELOG entries.
7. Never add `# noqa`, `# nosec` or `# type: ignore` to the package, skip a
   test, or loosen lint/type/coverage config. Fix the code.

## Done means

`poetry run pytest` (coverage >= 85%), `ruff check`, `ruff format --check`,
`mypy` (strict), `bandit`, `pip-audit` all green; docs and CHANGELOG updated.

## Git

Small commits, imperative subjects, never force-push `main`, never commit
secrets, `.env`, `cdk.out/` or `build/`.
