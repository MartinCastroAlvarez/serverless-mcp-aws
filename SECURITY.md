# Security

serverless-mcp-aws puts MCP servers on the public internet, in front of tools
that act with AWS credentials, and is installed by other people. Design goal:
nothing a caller, a browser page, a token or a model sends can make the server
act for someone it did not authenticate, call a tool its token does not grant,
forward the caller's credentials, or leak internals.

## Reporting a vulnerability

Open a private security advisory at
<https://github.com/MartinCastroAlvarez/serverless-mcp-aws/security/advisories/new>.
Do **not** open a public issue for a suspected vulnerability. We acknowledge
within 5 business days and aim to ship a fix within 30 days; you are credited
in the advisory unless you ask otherwise.

Supported versions: the latest minor release.

## 1. Threat model

**Assets.** The tools and the AWS resources behind them, the identities of
callers and the separation between them, the authorization server's tokens,
the function's IAM role, the availability (and the bill) of the deployment.

**Actors.**

| Actor | Controls | Must not be able to |
| --- | --- | --- |
| Remote client (agent, SDK, script) | HTTP method, path, headers, body, query string | call without a valid token, call tools outside its scopes, use a token minted for another service, exhaust the function |
| A web page in a user's browser | requests sent with the browser (incl. to `localhost` via DNS rebinding) | reach the MCP endpoint (Origin check), read responses (CORS) |
| Token forger | crafted JWTs, JWKS-looking URLs | get a token accepted by algorithm or key confusion |
| The model calling tools / tool output | tool arguments, text returned to the model | escape the caller's data, receive the caller's token, have stored text treated as instructions |
| Another service holding a token for itself | its own valid tokens | replay them against this server (confused deputy) |

**Threats and controls.**

| Threat | Control |
| --- | --- |
| DNS rebinding / cross-site requests | Every MCP request with an `Origin` header must match the exact allowlist (`scheme://host[:port]`, `http://localhost:*` for dev); otherwise 403 before authentication. `null` and wildcard origins are refused. Preflight answers only allowlisted origins, never with credentials. The dev server binds to 127.0.0.1 and refuses other addresses without `--allow-remote`. |
| Algorithm confusion (`alg=none`, HS256 with the RSA public key) | The allowlist can only hold `RS256`/`ES256` (others raise at construction). The token's `alg` must be in it before any key lookup; PyJWT is called with exactly that one algorithm and a key of the matching type. Tested with hand-built `none` and HMAC tokens. |
| `kid` confusion / key injection | Keys come only from the configured JWKS URL. A `kid` must name a key of the right type (`kty`, curve, `alg`); no `kid` is accepted only for a single-key JWKS. `jwk`, `jku`, `x5u`, `x5c` and `crit` headers are refused. Symmetric, encryption, weak (< 2048-bit RSA), non-P-256 and private-key JWKS entries are ignored. |
| Expired / not-yet-valid / foreign tokens | `exp`, `iss`, `aud`, `sub` required; `nbf` and `iat` checked with 30 s leeway; exact issuer; the audience must contain the server's canonical resource URI (RFC 8707). The handler refuses to start if the configured audience does not include the published resource. Authorizer-context mode re-checks `exp` (a cached decision may outlive the token). |
| Confused deputy / token passthrough | The MCP authorization spec forbids passing the client's token on. The token stops at the handler: `Authorization`, `Cookie` and session headers are stripped before the SDK, the SDK's `AccessToken.token` is empty, and the `Principal` tools receive carries identity and scopes only. Tools reach AWS with the function's own role, scoped per caller (the notes example keys objects by a hash of issuer + subject). A test plants a tool that dumps every header it can see. |
| Excess privilege per token | `ToolPolicy` maps scopes to tools, default deny; `tools/call` outside the grant is 403 `insufficient_scope` (or a JSON-RPC error inside a batch) and `tools/list` hides the tool. Filtered lists are marked `cacheScope: private`. |
| Token leakage | Tokens in the query string are refused (400). Tokens, bodies and tool arguments are never logged: one access-log line per request with HTTP method, a sanitised JSON-RPC method, status and duration. `InvalidToken` reasons are fixed strings, never token content; `WWW-Authenticate` values are fixed strings filtered to safe characters. |
| Resource exhaustion / cost | API Gateway stage throttling (10 rps, burst 20 by default; the construct refuses to disable it), optional reserved concurrency, body limit (1 MiB, checked before base64 decoding), batch limit (20), token limit (8 KiB, checked before parsing), JWKS limits (64 KiB, 3 s, no redirects) and an unknown-`kid` refresh limit (once per 60 s), so random `kid`s cannot turn the function into a load generator against the identity provider. Long-lived streams (`subscriptions/listen`) are refused. Per-caller rate limits need shared state; put them in the authorization server or API Gateway usage plans if you need them. |
| Error leakage | Unexpected exceptions become `500 {"code": -32603, "message": "Internal error"}`; the log line carries the exception type and traceback, not the request. The SDK reports only anticipated `ToolError` messages to the model. |
| Misconfiguration | No auth without `allow_anonymous=True`; auth without protected resource metadata, a tool policy without auth, SDK-level auth on the `MCPServer`, and a resource URI that is not https (except localhost) all raise at cold start. Routes behind an authorizer whose context is missing fail closed (401). |
| Code execution | No `eval`, `exec`, `pickle`, `yaml`, `subprocess` or shell in the package (an AST test enforces it, and that no `noqa`/`nosec`/`type: ignore` hides anything). |
| AWS blast radius (construct) | The function role can only write its own log group; no managed policies, no `*` resources (asserted on the template). Log groups are created up front with 1-day retention. Metadata and preflight routes are the only public routes when an authorizer is configured. |

**Prompt injection.** Tool results are data the model reads. The example
server's instructions tell the model never to follow instructions inside notes,
and `read_note` marks its result `untrusted_content: true`. Do the same for any
tool that returns text written by someone other than the caller.

## 2. Deploying safely (your account, your call)

- Use a custom domain and set `MCP_RESOURCE` to it; consider
  `disable_execute_api_endpoint=True` so tokens are only ever sent to one URI.
- Prefer short-lived access tokens (minutes) with `at+jwt` and `require_typ=True`.
- Keep the tool policy tight; give each tool its own IAM grant on the narrowest prefix.
- Keep `allowed_origins` empty unless a browser app truly needs to call the server.
- `MCPServer`'s multi-round-trip request state uses per-process keys by default;
  give it a shared `request_state_security` if you rely on MRTR across Lambda instances.

## 3. What this project never does

It never deploys, never calls AWS from tests (moto only), never contacts a real
identity provider (locally generated keys), and ships no telemetry.
