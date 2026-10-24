# Contributing to serverless-mcp-aws

## TL;DR

```bash
python3 -m venv .venv && . .venv/bin/activate && pip install poetry
poetry install --all-extras          # the cdk extra needs Node.js for the CDK tests
poetry run pytest
poetry run ruff check serverless_mcp_aws tests examples && poetry run ruff format --check serverless_mcp_aws tests examples
poetry run mypy serverless_mcp_aws
poetry run bandit -c pyproject.toml -q -r serverless_mcp_aws
poetry run pip-audit
poetry run python -m examples.local_demo
```

Open a PR against `main` from a `feat/…`, `fix/…`, `docs/…` or `chore/…` branch.

## What this package will not accept

- Anything that deploys, or tests that need AWS credentials, a real identity
  provider or network access (moto, local keys and loopback servers only).
- Symmetric JWT algorithms, `none`, keys from token headers, or tokens in URLs.
- Passing the caller's bearer token to tool code or to another service.
- Logging tokens, request bodies or tool arguments.
- Server-side sessions or long-lived streams on Lambda.
- IAM `*` resources or managed policies in the construct.

## What it does accept

- Support for new MCP revisions as the SDK adds them (with event-level tests).
- More authenticators (e.g. token introspection) behind the `Authenticator` protocol.
- Construct options that keep least privilege (with CDK assertions).

## House rules

1. Tests alongside features; security-relevant changes get a hostile case.
2. README, ARCHITECTURE/SECURITY (when relevant) and CHANGELOG change with the code.
3. No secrets in commits; `.env.example` holds placeholders only.

## Releasing

1. Bump `version` in `pyproject.toml` and `__version__` in
   `serverless_mcp_aws/__init__.py`; move `Unreleased` in `CHANGELOG.md` under the new version.
2. Merge, tag the merge commit `vX.Y.Z`, push the tag. `publish.yml` checks
   tag == version, runs the tests, scans the artefacts and publishes through
   PyPI Trusted Publishing (environment `pypi`), then creates the GitHub Release.
   The PyPI pending publisher must be registered first
   (owner `MartinCastroAlvarez`, repository `serverless-mcp-aws`, workflow `publish.yml`, environment `pypi`).
