# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### To do before the first PyPI release
- Register the PyPI pending publisher for `publish.yml` (environment `pypi`),
  then tag `v0.1.0`.

## [0.1.0] — unreleased

### Added
- `lambda_handler_for(server, ...)` / `McpLambdaHandler`: API Gateway HTTP API
  (payload 2.0) events to the official `mcp` SDK (2.x) in stateless JSON mode,
  for both the 2026-07-28 per-request envelope and the 2025 handshake revisions.
- JSON-RPC batches for protocol 2025-03-26 (size-limited, no `initialize`),
  refused for later revisions; `Mcp-Session-Id` ignored and never minted;
  `GET`/`DELETE` 405; `subscriptions/listen` 404.
- Origin allowlist with CORS preflight; body, batch and token size limits;
  tokens in the query string refused.
- `JWTVerifier` (PyJWT): RS256/ES256 only, JWKS cache with TTL and rate-limited
  refresh, issuer/audience/expiry/nbf checks, key-type and header hardening.
- `BearerAuth`, `AuthorizerContextAuth` (Lambda or API Gateway JWT authorizer
  context) and `authorizer_handler_for` (Lambda REQUEST authorizer).
- `ToolPolicy` (scopes to tools, default deny) with 403 `insufficient_scope`
  challenges and filtered `tools/list`.
- `ProtectedResourceMetadata` (RFC 9728) at both well-known paths and
  `WWW-Authenticate` challenges with `resource_metadata` and `scope`.
- `current_principal()` for tools; the bearer token never reaches tool code.
- `serverless-mcp-aws dev module:attr`: local HTTP server running the same
  handler, with optional Lambda authorizer emulation.
- `serverless_mcp_aws.cdk.McpServerFunction` (`cdk` extra): Lambda, HTTP API,
  throttled stage, optional Lambda/JWT authorizer, least-privilege IAM, 1-day logs.
- Notes example on S3 (moto in tests), CDK app (synth only) and a fully local demo.
