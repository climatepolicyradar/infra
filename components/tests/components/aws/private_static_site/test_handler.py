"""PrivateStaticSite's sign-in Lambda against a fake Google: our own RSA keys stand in for Google's and CloudFront's.

Ported from architecture-hub PR #44 (infra/auth/tests).
"""

import base64
import json
import time
import urllib.parse
from http import HTTPStatus

import jwt
import pytest
from components.aws.private_static_site.auth import handler
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

DOMAIN = "arch.example.org"
CLIENT_ID = "client-123.apps.googleusercontent.com"
HD = "climatepolicyradar.org"
TX_COOKIE = "__Host-test-site-auth"

GOOGLE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
CF_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class FakeJWKS:
    def get_signing_key_from_jwt(self, token):
        return jwt.PyJWK.from_dict(
            {
                **json.loads(
                    jwt.algorithms.RSAAlgorithm.to_jwk(GOOGLE_KEY.public_key())
                ),
                "alg": "RS256",
            }
        )


@pytest.fixture(autouse=True)
def setup(monkeypatch):
    for k, v in {
        "DOMAIN": DOMAIN,
        "GOOGLE_CLIENT_ID": CLIENT_ID,
        "ALLOWED_HD": HD,
        "KEY_PAIR_ID": "K2TESTKEY",
        "SECRET_ID": "unused",
        "SESSION_HOURS": "12",
        "TX_COOKIE": TX_COOKIE,
        "SITE_TITLE": "Test <site>",
    }.items():
        monkeypatch.setenv(k, v)
    pem = CF_KEY.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    monkeypatch.setattr(
        handler,
        "_secrets",
        lambda: {"google_client_secret": "s", "cloudfront_private_key": pem},
    )
    handler._private_key.cache_clear()
    monkeypatch.setattr(handler, "_jwks", FakeJWKS())


def start_login(rd="/systems/data/", **query):
    r = handler.handler(
        {"rawPath": "/_auth/login", "queryStringParameters": {"rd": rd, **query}}
    )
    params = dict(
        urllib.parse.parse_qsl(urllib.parse.urlsplit(r["headers"]["Location"]).query)
    )
    cookie = r["cookies"][0].split(";")[0]
    return r, params, cookie


def id_token(expected_nonce, **overrides):
    now = int(time.time())
    claims = {
        "iss": "https://accounts.google.com",
        "aud": CLIENT_ID,
        "sub": "1234",
        "iat": now,
        "exp": now + 3600,
        "nonce": expected_nonce,
        "email": "someone@climatepolicyradar.org",
        "email_verified": True,
        "hd": HD,
    } | overrides
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, GOOGLE_KEY, algorithm="RS256", headers={"kid": "k1"})


def finish(monkeypatch, token=None, state=None, rd="/systems/data/", **claims):
    _, params, cookie = start_login(rd)
    token = token or id_token(params["nonce"], **claims)
    monkeypatch.setattr(handler, "exchange_code", lambda code, verifier: token)
    return handler.handler(
        {
            "rawPath": "/_auth/callback",
            "queryStringParameters": {"code": "c", "state": state or params["state"]},
            "cookies": [cookie],
        }
    )


def cookie_values(r):
    return dict(c.split(";")[0].split("=", 1) for c in r["cookies"])


def from_cf_b64(s):
    return base64.b64decode(s.translate(str.maketrans("-_~", "+=/")))


def test_login_redirects_to_google_with_pkce_and_hd_hint():
    r, params, cookie = start_login()
    assert r["statusCode"] == HTTPStatus.FOUND
    assert r["headers"]["Location"].startswith(
        "https://accounts.google.com/o/oauth2/v2/auth?"
    )
    assert params["redirect_uri"] == f"https://{DOMAIN}/_auth/callback"
    assert params["scope"] == "openid email"
    assert params["code_challenge_method"] == "S256"
    assert params["hd"] == HD
    assert "prompt" not in params
    assert cookie.startswith(f"{TX_COOKIE}=")
    assert (
        "Secure" in r["cookies"][0]
        and "HttpOnly" in r["cookies"][0]
        and "Domain" not in r["cookies"][0]
    )


def test_switch_asks_google_for_the_account_chooser():
    _, params, _ = start_login(switch="1")
    assert params["prompt"] == "select_account"


def test_allowed_account_gets_signed_cookies_and_its_page(monkeypatch):
    r = finish(monkeypatch)
    assert r["statusCode"] == HTTPStatus.FOUND
    assert r["headers"]["Location"] == "/systems/data/"
    values = cookie_values(r)
    assert values["CloudFront-Key-Pair-Id"] == "K2TESTKEY"
    assert values[TX_COOKIE] == ""
    policy = from_cf_b64(values["CloudFront-Policy"])
    CF_KEY.public_key().verify(
        from_cf_b64(values["CloudFront-Signature"]),
        policy,
        padding.PKCS1v15(),
        hashes.SHA1(),
    )
    stmt = json.loads(policy)["Statement"][0]
    assert stmt["Resource"] == f"https://{DOMAIN}/*"
    assert (
        11.9 * 3600
        < stmt["Condition"]["DateLessThan"]["AWS:EpochTime"] - time.time()
        <= 12 * 3600
    )
    for c in r["cookies"]:
        assert (
            "Secure" in c
            and "HttpOnly" in c
            and "SameSite=Lax" in c
            and "Domain" not in c
        )


@pytest.mark.parametrize(
    "claims, reason",
    [
        ({"hd": "gmail.com"}, "hd"),
        ({"hd": None, "email": "someone@gmail.com"}, "hd"),
        ({"hd": "climatepolicyradar.org.evil.com"}, "hd"),
        ({"email_verified": False}, "email_unverified"),
        ({"email_verified": None}, "email_unverified"),
        ({"email_verified": "true"}, "email_unverified"),
        ({"exp": int(time.time()) - 120}, "token_ExpiredSignatureError"),
        ({"aud": "someone-else"}, "token_InvalidAudienceError"),
        ({"iss": "https://evil.example"}, "token_InvalidIssuerError"),
        ({"nonce": "not-the-nonce"}, "nonce"),
    ],
)
def test_refused_tokens_set_no_cloudfront_cookies(monkeypatch, capsys, claims, reason):
    r = finish(monkeypatch, **claims)
    assert r["statusCode"] == HTTPStatus.UNAUTHORIZED
    assert not any(c.startswith("CloudFront-") for c in r["cookies"])
    assert (
        json.loads(capsys.readouterr().out.strip().splitlines()[-1])["reason"] == reason
    )


def test_token_signed_by_another_key_is_refused(monkeypatch):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _, params, _ = start_login()
    forged = jwt.encode(
        jwt.decode(id_token(params["nonce"]), options={"verify_signature": False}),
        other,
        algorithm="RS256",
    )
    r = finish(monkeypatch, token=forged)
    assert r["statusCode"] == HTTPStatus.UNAUTHORIZED
    assert not any(c.startswith("CloudFront-") for c in r["cookies"])


def test_state_mismatch_is_refused_before_the_code_is_used(monkeypatch):
    called = []
    monkeypatch.setattr(handler, "exchange_code", lambda *a: called.append(a))
    _, _, cookie = start_login()
    r = handler.handler(
        {
            "rawPath": "/_auth/callback",
            "queryStringParameters": {"code": "c", "state": "forged"},
            "cookies": [cookie],
        }
    )
    assert r["statusCode"] == HTTPStatus.UNAUTHORIZED and not called


def test_callback_without_the_login_cookie_is_refused():
    r = handler.handler(
        {
            "rawPath": "/_auth/callback",
            "queryStringParameters": {"code": "c", "state": "s"},
        }
    )
    assert r["statusCode"] == HTTPStatus.UNAUTHORIZED


def test_denial_logs_the_email_and_success_does_not(monkeypatch, capsys):
    finish(monkeypatch, hd="gmail.com", email="x@gmail.com")
    assert json.loads(capsys.readouterr().out.strip())["email"] == "x@gmail.com"
    finish(monkeypatch)
    assert "email" not in json.loads(capsys.readouterr().out.strip())


def test_denial_page_escapes_the_email(monkeypatch):
    r = finish(monkeypatch, hd="gmail.com", email="<script>@gmail.com")
    assert "<script>" not in r["body"] and "&lt;script&gt;" in r["body"]


@pytest.mark.parametrize(
    "rd",
    [
        "//evil.example/x",
        "/\\evil.example",
        "https://evil.example/",
        "javascript:alert(1)",
        "evil.example",
        "",
        "/ok\r\nSet-Cookie: x=1",
        "/_auth/login",
        "/" + "a" * 3000,
    ],
)
def test_rd_outside_the_site_goes_home(monkeypatch, rd):
    assert handler.safe_rd(rd) == "/"
    assert finish(monkeypatch, rd=rd)["headers"]["Location"] == "/"


@pytest.mark.parametrize(
    "rd", ["/", "/systems/data/", "/node/component/x/?tab=impact#runs", "/%2F%2Fevil"]
)
def test_rd_on_the_site_is_kept(rd):
    assert handler.safe_rd(rd) == rd


def test_logout_clears_the_cloudfront_cookies():
    r = handler.handler({"rawPath": "/_auth/logout"})
    assert r["statusCode"] == HTTPStatus.FOUND and r["headers"]["Location"] == "/"
    assert {c.split("=")[0] for c in r["cookies"]} == set(handler.CF_COOKIES)
    assert all("Max-Age=0" in c for c in r["cookies"])


def test_unknown_auth_path_is_404():
    assert (
        handler.handler({"rawPath": "/_auth/anything"})["statusCode"]
        == HTTPStatus.NOT_FOUND
    )


def test_session_length_comes_from_session_hours(monkeypatch):
    monkeypatch.setenv("SESSION_HOURS", "3")
    values = cookie_values(finish(monkeypatch))
    expires = json.loads(from_cf_b64(values["CloudFront-Policy"]))["Statement"][0][
        "Condition"
    ]["DateLessThan"]
    assert 2.9 * 3600 < expires["AWS:EpochTime"] - time.time() <= 3 * 3600


def test_pages_carry_the_escaped_site_title(monkeypatch):
    r = finish(monkeypatch, hd="gmail.com")
    assert "<title>Not signed in · Test &lt;site&gt;</title>" in r["body"]
