"""JWT verification, including the attacks it must refuse."""

from __future__ import annotations

import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa

from serverless_mcp_aws import InvalidToken
from serverless_mcp_aws import JWKSCache
from serverless_mcp_aws import JWTVerifier
from serverless_mcp_aws.auth import jwt as jwt_mod
from tests.conftest import EC_KEY
from tests.conftest import ISSUER
from tests.conftest import JWKS_URL
from tests.conftest import RESOURCE
from tests.conftest import RSA_KEY
from tests.conftest import RSA_KEY_2
from tests.conftest import FakeJWKS
from tests.conftest import b64url
from tests.conftest import make_token
from tests.conftest import public_jwk


def refused(verifier: JWTVerifier, token: str, reason: str) -> None:
    with pytest.raises(InvalidToken) as info:
        verifier.verify(token)
    assert info.value.reason == reason


# --------------------------------------------------------------------------- #
# Accepted tokens
# --------------------------------------------------------------------------- #
def test_rs256_token_is_accepted(verifier: JWTVerifier) -> None:
    principal = verifier.verify(make_token())
    assert principal.subject == "alice"
    assert principal.issuer == ISSUER
    assert principal.client_id == "cli-1"
    assert principal.scopes == {"notes:read", "notes:write"}
    assert principal.audience == (RESOURCE,)
    assert principal.expires_at and principal.expires_at > time.time()
    assert len(principal.key) == 32


def test_es256_token_is_accepted(verifier: JWTVerifier) -> None:
    assert verifier.verify(make_token("ES256", kid="ec-1")).subject == "alice"


def test_scp_list_claim_and_azp(verifier: JWTVerifier) -> None:
    token = make_token(scope=None, scp=["a", "b", 3, "bad scope"], client_id=None, azp="web")
    principal = verifier.verify(token)
    assert principal.scopes == {"a", "b"}
    assert principal.client_id == "web"


def test_audience_list_containing_the_resource(verifier: JWTVerifier) -> None:
    token = make_token(aud=["https://other.example.com", RESOURCE])
    assert verifier.verify(token).audience == ("https://other.example.com", RESOURCE)


def test_at_jwt_typ_is_accepted_and_can_be_required(jwks: FakeJWKS) -> None:
    strict = JWTVerifier(
        issuer=ISSUER, audience=RESOURCE, jwks_url=JWKS_URL, fetcher=jwks, require_typ=True
    )
    assert strict.verify(make_token(headers={"typ": "at+jwt"})).subject == "alice"
    refused(strict, make_token(headers={"typ": "JWT"}), "wrong token type")


def test_leeway_tolerates_small_clock_skew(verifier: JWTVerifier) -> None:
    assert verifier.verify(make_token(exp=int(time.time()) - 10)).subject == "alice"


def test_single_key_jwks_without_kid() -> None:
    fetch = FakeJWKS([public_jwk(RSA_KEY, "only", None)])
    v = JWTVerifier(issuer=ISSUER, audience=RESOURCE, jwks_url=JWKS_URL, fetcher=fetch)
    assert v.verify(make_token(kid=None)).subject == "alice"


# --------------------------------------------------------------------------- #
# Claims
# --------------------------------------------------------------------------- #
def test_expired(verifier: JWTVerifier) -> None:
    refused(verifier, make_token(exp=int(time.time()) - 3600), "token expired")


def test_not_yet_valid(verifier: JWTVerifier) -> None:
    refused(verifier, make_token(nbf=int(time.time()) + 3600), "token not yet valid")


def test_issued_in_the_future(verifier: JWTVerifier) -> None:
    refused(verifier, make_token(iat=int(time.time()) + 3600), "token not yet valid")


def test_wrong_audience(verifier: JWTVerifier) -> None:
    refused(verifier, make_token(aud="https://other.example.com/mcp"), "invalid audience")


def test_audience_prefix_is_not_enough(verifier: JWTVerifier) -> None:
    refused(verifier, make_token(aud=RESOURCE + "-evil"), "invalid audience")


def test_wrong_issuer(verifier: JWTVerifier) -> None:
    refused(verifier, make_token(iss="https://evil.example.com"), "invalid issuer")


def test_issuer_prefix_is_not_enough(verifier: JWTVerifier) -> None:
    refused(verifier, make_token(iss=ISSUER + ".evil.com"), "invalid issuer")


@pytest.mark.parametrize("claim", ["exp", "aud", "iss", "sub"])
def test_missing_required_claims(verifier: JWTVerifier, claim: str) -> None:
    refused(verifier, make_token(**{claim: None}), "missing required claim")


def test_empty_subject(verifier: JWTVerifier) -> None:
    refused(verifier, make_token(sub=""), "missing required claim")


# --------------------------------------------------------------------------- #
# Algorithm attacks
# --------------------------------------------------------------------------- #
def test_alg_none_is_refused(verifier: JWTVerifier) -> None:
    header = b64url(json.dumps({"alg": "none", "typ": "JWT", "kid": "rsa-1"}).encode())
    payload = b64url(
        json.dumps({"iss": ISSUER, "aud": RESOURCE, "sub": "x", "exp": 9999999999}).encode()
    )
    refused(verifier, f"{header}.{payload}.", "algorithm not allowed")


def test_hs256_signed_with_the_public_key_is_refused(verifier: JWTVerifier) -> None:
    """The classic RS256 -> HS256 key-confusion attack."""
    pem = RSA_KEY.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "rsa-1"}).encode())
    payload = b64url(
        json.dumps({"iss": ISSUER, "aud": RESOURCE, "sub": "x", "exp": 9999999999}).encode()
    )
    import hashlib
    import hmac

    sig = hmac.new(pem, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    refused(verifier, f"{header}.{payload}.{b64url(sig)}", "algorithm not allowed")


def test_algorithm_outside_the_allowlist(verifier: JWTVerifier) -> None:
    refused(verifier, make_token("RS384"), "algorithm not allowed")
    refused(verifier, make_token("PS256"), "algorithm not allowed")


def test_allowlist_narrowed_to_es256(jwks: FakeJWKS) -> None:
    v = JWTVerifier(
        issuer=ISSUER, audience=RESOURCE, jwks_url=JWKS_URL, fetcher=jwks, algorithms=["ES256"]
    )
    refused(v, make_token("RS256"), "algorithm not allowed")
    assert v.verify(make_token("ES256", kid="ec-1")).subject == "alice"


@pytest.mark.parametrize("alg", ["none", "HS256", "HS512", "RS384", "EdDSA"])
def test_unsafe_algorithms_cannot_be_configured(alg: str) -> None:
    with pytest.raises(ValueError, match="refusing algorithms"):
        JWTVerifier(issuer=ISSUER, audience=RESOURCE, jwks_url=JWKS_URL, algorithms=[alg])


def test_es256_token_with_an_rsa_kid_is_refused(verifier: JWTVerifier) -> None:
    """kid confusion: point an EC-signed token at the RSA key."""
    refused(verifier, make_token("ES256", kid="rsa-1"), "unknown signing key")


def test_rs256_token_with_an_ec_kid_is_refused(verifier: JWTVerifier) -> None:
    refused(verifier, make_token("RS256", kid="ec-1"), "unknown signing key")


def test_kid_of_one_key_signed_by_another(jwks: FakeJWKS) -> None:
    jwks.keys.append(public_jwk(RSA_KEY_2, "rsa-2", "RS256"))
    v = JWTVerifier(issuer=ISSUER, audience=RESOURCE, jwks_url=JWKS_URL, fetcher=jwks)
    refused(v, make_token(kid="rsa-2", key=RSA_KEY), "invalid signature")


def test_attacker_key_is_refused(verifier: JWTVerifier) -> None:
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    refused(verifier, make_token(key=attacker), "invalid signature")


@pytest.mark.parametrize("header", ["jwk", "jku", "x5u", "x5c", "crit"])
def test_key_injection_headers_are_refused(verifier: JWTVerifier, header: str) -> None:
    value = (
        public_jwk(RSA_KEY, "inline", "RS256")
        if header == "jwk"
        else ["exp"]
        if header == "crit"
        else ["x"]
        if header == "x5c"
        else "https://evil.example.com/jwks.json"
    )
    token = make_token(headers={header: value})
    with pytest.raises(InvalidToken) as info:
        verifier.verify(token)
    # PyJWT already rejects unknown `crit` extensions while decoding the header.
    assert info.value.reason in ("forbidden token header", "malformed token")


def test_kid_must_be_a_short_string(verifier: JWTVerifier) -> None:
    refused(verifier, make_token(kid="k" * 300), "malformed token")


def test_ambiguous_jwks_requires_kid(verifier: JWTVerifier, jwks: FakeJWKS) -> None:
    jwks.keys.append(public_jwk(RSA_KEY_2, "rsa-2", "RS256"))
    refused(verifier, make_token(kid=None), "token has no kid")


def test_wrong_typ_is_refused(verifier: JWTVerifier) -> None:
    refused(verifier, make_token(headers={"typ": "id_token+jwt"}), "wrong token type")


# --------------------------------------------------------------------------- #
# Shape and size
# --------------------------------------------------------------------------- #
def test_oversized_token_is_refused_before_parsing(verifier: JWTVerifier, jwks: FakeJWKS) -> None:
    big = make_token(pad="x" * 10_000)
    refused(verifier, big, "token too large")
    assert jwks.calls == 0


@pytest.mark.parametrize(
    "token", ["abc", "a.b", "a.b.c.d", "!!!.###.$$$", "eyJhbGciOiJSUzI1NiJ9.e30"]
)
def test_malformed_tokens(verifier: JWTVerifier, token: str) -> None:
    refused(verifier, token, "malformed token")


def test_empty_token(verifier: JWTVerifier) -> None:
    refused(verifier, "", "missing token")


def test_tampered_payload_is_refused(verifier: JWTVerifier) -> None:
    head, _payload, sig = make_token().split(".")
    forged = b64url(
        json.dumps(
            {"iss": ISSUER, "aud": RESOURCE, "sub": "admin", "exp": 9999999999, "scope": "admin"}
        ).encode()
    )
    refused(verifier, f"{head}.{forged}.{sig}", "invalid signature")


# --------------------------------------------------------------------------- #
# JWKS handling
# --------------------------------------------------------------------------- #
def test_jwks_is_cached(verifier: JWTVerifier, jwks: FakeJWKS) -> None:
    for _ in range(5):
        verifier.verify(make_token())
    assert jwks.calls == 1


def test_unknown_kid_refreshes_once_then_rate_limits(jwks: FakeJWKS) -> None:
    now = [1000.0]
    cache = JWKSCache(JWKS_URL, fetcher=jwks, clock=lambda: now[0], min_refresh_interval=60)
    cache.find("rsa-1", "RS256")
    assert jwks.calls == 1
    for _ in range(10):
        with pytest.raises(InvalidToken):
            cache.find("random-kid", "RS256")
    assert jwks.calls == 1  # inside the refresh interval
    now[0] += 61
    with pytest.raises(InvalidToken):
        cache.find("random-kid", "RS256")
    assert jwks.calls == 2


def test_key_rotation_is_picked_up(jwks: FakeJWKS) -> None:
    now = [1000.0]
    cache = JWKSCache(JWKS_URL, fetcher=jwks, clock=lambda: now[0], min_refresh_interval=60)
    cache.keys()
    jwks.keys = [public_jwk(RSA_KEY_2, "rsa-2", "RS256")]
    now[0] += 61
    assert cache.find("rsa-2", "RS256") is not None


def test_ttl_expiry_refetches(jwks: FakeJWKS) -> None:
    now = [0.0]
    cache = JWKSCache(JWKS_URL, fetcher=jwks, clock=lambda: now[0], ttl=600)
    cache.keys()
    now[0] += 601
    cache.keys()
    assert jwks.calls == 2


def test_failed_refresh_keeps_old_keys(jwks: FakeJWKS) -> None:
    now = [0.0]
    cache = JWKSCache(JWKS_URL, fetcher=jwks, clock=lambda: now[0], ttl=10)
    cache.keys()
    jwks.fail = True
    now[0] += 100
    assert cache.find("rsa-1", "RS256") is not None


def test_jwks_down_at_cold_start_refuses_then_recovers(jwks: FakeJWKS) -> None:
    now = [0.0]
    jwks.fail = True
    cache = JWKSCache(JWKS_URL, fetcher=jwks, clock=lambda: now[0], min_refresh_interval=5)
    with pytest.raises(InvalidToken):
        cache.find("rsa-1", "RS256")
    jwks.fail = False
    now[0] += 6
    assert cache.find("rsa-1", "RS256") is not None


def test_unusable_keys_are_skipped() -> None:
    small = rsa.generate_private_key(public_exponent=65537, key_size=1024)  # noqa: S505 - the weak key under test
    p384 = ec.generate_private_key(ec.SECP384R1())
    private = public_jwk(RSA_KEY, "priv", "RS256")
    private["d"] = "AAAA"
    keys = [
        {"kty": "oct", "k": "c2VjcmV0", "kid": "hmac"},
        {**public_jwk(RSA_KEY, "enc", "RS256"), "use": "enc"},
        public_jwk(RSA_KEY, "hs", "HS256"),
        public_jwk(small, "small", "RS256"),
        public_jwk(p384, "p384", None),
        private,
        {"kty": "RSA", "kid": "broken", "n": "!!", "e": "AQAB"},
        "not-a-dict",
    ]
    parsed = jwt_mod._parse_jwks(json.dumps({"keys": keys}).encode())
    assert parsed == []


@pytest.mark.parametrize("raw", [b"not json", b"[]", b'{"keys": 3}'])
def test_bad_jwks_documents(raw: bytes) -> None:
    with pytest.raises(OSError):
        jwt_mod._parse_jwks(raw)


@pytest.mark.parametrize(
    "url", ["http://auth.example.com/jwks", "ftp://x/jwks", "file:///etc/passwd", "jwks.json"]
)
def test_jwks_url_must_be_https(url: str) -> None:
    with pytest.raises(ValueError):
        JWKSCache(url)


def test_loopback_http_jwks_is_allowed_for_local_development() -> None:
    assert JWKSCache("http://127.0.0.1:9000/jwks").url.startswith("http://127.0.0.1")
    assert JWKSCache("http://localhost:9000/jwks").url.startswith("http://localhost")


def test_fetch_url_refuses_plain_http_to_remote_hosts() -> None:
    with pytest.raises(ValueError):
        jwt_mod.fetch_url("http://example.com/jwks")


def test_fetch_url_against_a_local_server() -> None:
    import threading
    from http.server import BaseHTTPRequestHandler
    from http.server import HTTPServer

    doc = json.dumps({"keys": [public_jwk(RSA_KEY, "rsa-1", "RS256")]}).encode()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a: object) -> None:
            pass

        def do_GET(self) -> None:
            if self.path.startswith("/big"):
                body = b"x" * 70_000
            elif self.path.startswith("/missing"):
                self.send_response(404)
                self.end_headers()
                return
            else:
                body = doc
            self.send_response(200)
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        base = f"http://127.0.0.1:{httpd.server_address[1]}"
        assert jwt_mod.fetch_url(f"{base}/jwks?x=1") == doc
        with pytest.raises(OSError, match="too large"):
            jwt_mod.fetch_url(f"{base}/big")
        with pytest.raises(OSError, match="404"):
            jwt_mod.fetch_url(f"{base}/missing")
        v = JWTVerifier(issuer=ISSUER, audience=RESOURCE, jwks_url=f"{base}/jwks")
        assert v.verify(make_token()).subject == "alice"
    finally:
        httpd.shutdown()
        httpd.server_close()


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
def test_from_env() -> None:
    v = JWTVerifier.from_env(
        {
            "MCP_JWT_ISSUER": ISSUER,
            "MCP_JWT_JWKS_URL": JWKS_URL,
            "MCP_RESOURCE": RESOURCE,
            "MCP_JWT_ALGORITHMS": "ES256",
        }
    )
    assert v.audience == (RESOURCE,)
    assert v.algorithms == {"ES256"}


def test_from_env_missing() -> None:
    with pytest.raises(ValueError, match="MCP_JWT_ISSUER"):
        JWTVerifier.from_env({})


@pytest.mark.parametrize(
    "kwargs",
    [
        {"issuer": ""},
        {"audience": ""},
        {"audience": []},
        {"algorithms": []},
    ],
)
def test_bad_configuration(kwargs: dict[str, object]) -> None:
    base: dict[str, object] = {"issuer": ISSUER, "audience": RESOURCE, "jwks_url": JWKS_URL}
    base.update(kwargs)
    with pytest.raises(ValueError):
        JWTVerifier(**base)  # type: ignore[arg-type]


def test_reasons_never_echo_token_content(verifier: JWTVerifier) -> None:
    token = make_token(iss="https://evil.example.com/<script>")
    with pytest.raises(InvalidToken) as info:
        verifier.verify(token)
    assert "evil" not in str(info.value)
    assert token not in str(info.value)


def test_pyjwt_itself_refuses_hmac_with_a_pem_key() -> None:
    """Belt and braces: even PyJWT refuses a PEM public key as an HMAC secret."""
    pem = RSA_KEY.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with pytest.raises(jwt.InvalidKeyError):
        jwt.encode({"a": 1}, pem, algorithm="HS256")
    assert EC_KEY is not None
