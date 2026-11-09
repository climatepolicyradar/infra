"""Sign-in for a PrivateStaticSite: Google in, CloudFront signed cookies out.

A Lambda Function URL behind CloudFront's unsigned `/_auth/*` behaviour:

- `/_auth/login?rd=/path` starts Google's code flow. State, nonce and the PKCE verifier ride in a
  short-lived `__Host-` cookie named TX_COOKIE.
- `/_auth/callback` exchanges the code, verifies the id_token against Google's keys (signature, `iss`,
  `aud`, `exp`, `nonce`), admits only `email_verified` accounts whose `hd` is ALLOWED_HD, then sets the
  three CloudFront cookies for SESSION_HOURS and redirects to `rd`.
- `/_auth/logout` clears the CloudFront cookies.

CloudFront checks the cookies itself on every other request, so static pages never depend on this
function: an outage stops new sign-ins only. Each attempt logs one JSON line with its outcome and reason,
and the email only on denials.

Configured by the component through environment variables: DOMAIN, ALLOWED_HD, GOOGLE_CLIENT_ID,
SECRET_ID, KEY_PAIR_ID, SESSION_HOURS, TX_COOKIE and SITE_TITLE.
"""

import base64
import hashlib
import html
import json
import os
import secrets
import time
import urllib.parse
import urllib.request
from functools import cache
from typing import Any

import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = (
    "https://oauth2.googleapis.com/token"  # nosec B105: a URL, not a password
)
GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUERS = ("https://accounts.google.com", "accounts.google.com")

TX_SECONDS = 600
MAX_RD = 2048
CONTROL_CHARS = frozenset(chr(c) for c in [*range(0x20), 0x7F])
CF_COOKIES = ("CloudFront-Policy", "CloudFront-Signature", "CloudFront-Key-Pair-Id")

_jwks = jwt.PyJWKClient(GOOGLE_JWKS_URL, cache_keys=True, lifespan=3600, timeout=5)


def env(name: str) -> str:
    return os.environ[name]


def tx_cookie() -> str:
    """The sign-in transaction cookie's name; `__Host-` keeps it host-only, Secure and on Path=/."""
    return env("TX_COOKIE")


@cache
def _secrets() -> dict[str, str]:
    """`{"google_client_secret", "cloudfront_private_key"}` from Secrets Manager, read once per container."""
    import boto3  # noqa: PLC0415  in the Lambda runtime; imported here so tests need no AWS

    raw = boto3.client("secretsmanager").get_secret_value(SecretId=env("SECRET_ID"))[
        "SecretString"
    ]
    return json.loads(raw)


@cache
def _private_key() -> Any:
    return serialization.load_pem_private_key(
        _secrets()["cloudfront_private_key"].encode(), password=None
    )


def handler(event: dict, context: object = None) -> dict:
    path = event.get("rawPath", "")
    query = event.get("queryStringParameters") or {}
    cookies = _parse_cookies(event.get("cookies") or [])
    if path == "/_auth/login":
        return login(query)
    if path == "/_auth/callback":
        return callback(query, cookies)
    if path == "/_auth/logout":
        return logout()
    return _page(404, "Not found", "<p>There is nothing here.</p>")


def safe_rd(rd: str | None) -> str:
    """`rd` if it is a path on this site, else `/`: one leading slash, no scheme, host or backslash."""
    if (
        not rd
        or len(rd) > MAX_RD
        or not rd.startswith("/")
        or rd.startswith("//")
        or "\\" in rd
    ):
        return "/"
    if any(c in CONTROL_CHARS for c in rd) or rd.startswith("/_auth/"):
        return "/"
    parts = urllib.parse.urlsplit(rd)
    if parts.scheme or parts.netloc:
        return "/"
    return rd


def login(query: dict[str, str]) -> dict:
    state, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(3))
    challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
    params = {
        "client_id": env("GOOGLE_CLIENT_ID"),
        "redirect_uri": _redirect_uri(),
        "response_type": "code",
        "scope": "openid email",
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "hd": env(
            "ALLOWED_HD"
        ),  # a hint for Google's account chooser only; the callback checks the claim
    }
    if "switch" in query:
        params["prompt"] = "select_account"
    tx = {
        "state": state,
        "nonce": nonce,
        "verifier": verifier,
        "rd": safe_rd(query.get("rd")),
    }
    return _redirect(
        f"{GOOGLE_AUTH_URL}?{urllib.parse.urlencode(params)}",
        [_cookie(tx_cookie(), _b64url(json.dumps(tx).encode()), TX_SECONDS)],
    )


def callback(  # noqa: PLR0911  one return per refusal
    query: dict[str, str], cookies: dict[str, str]
) -> dict:
    tx = _read_tx(cookies.get(tx_cookie()))
    if tx is None or not secrets.compare_digest(query.get("state", ""), tx["state"]):
        return _deny("state", "Your sign-in took too long or was started elsewhere.")
    if "error" in query:
        return _deny("google_" + query["error"][:40], "Google did not sign you in.")
    if "code" not in query:
        return _deny("no_code", "Google did not sign you in.")

    try:
        id_token = exchange_code(query["code"], tx["verifier"])
    # Any failure to reach Google is the same to the person.
    except Exception as e:  # noqa: BLE001
        _log("error", "token_exchange", detail=type(e).__name__)
        return _page(
            502,
            "Sign-in failed",
            '<p>Google did not answer. <a href="/_auth/login">Try again</a>.</p>',
        )

    try:
        claims = verify_id_token(id_token)
    except jwt.PyJWTError as e:
        return _deny(
            "token_" + type(e).__name__, "Google's answer could not be verified."
        )
    if not secrets.compare_digest(str(claims.get("nonce", "")), tx["nonce"]):
        return _deny("nonce", "Your sign-in could not be matched to this browser.")
    email = str(claims.get("email", ""))
    if claims.get("email_verified") is not True:
        return _deny(
            "email_unverified", "Your Google account's email is not verified.", email
        )
    if claims.get("hd") != env("ALLOWED_HD"):
        return _deny(
            "hd",
            f"This site is only for {html.escape(env('ALLOWED_HD'))} accounts.",
            email,
        )

    hours = int(env("SESSION_HOURS"))
    _log("allow", "ok")
    return _redirect(
        safe_rd(tx["rd"]),
        [*signed_cookies(int(time.time()) + hours * 3600), _expire(tx_cookie())],
    )


def logout() -> dict:
    return _redirect("/", [_expire(name) for name in CF_COOKIES])


def exchange_code(code: str, verifier: str) -> str:
    """The id_token Google returns for `code`."""
    form = urllib.parse.urlencode(
        {
            "code": code,
            "client_id": env("GOOGLE_CLIENT_ID"),
            "client_secret": _secrets()["google_client_secret"],
            "redirect_uri": _redirect_uri(),
            "grant_type": "authorization_code",
            "code_verifier": verifier,
        }
    ).encode()
    with urllib.request.urlopen(  # nosec B310: a fixed https URL
        urllib.request.Request(GOOGLE_TOKEN_URL, data=form), timeout=5
    ) as r:
        return json.load(r)["id_token"]


def verify_id_token(id_token: str) -> dict:
    key = _jwks.get_signing_key_from_jwt(id_token)
    return jwt.decode(
        id_token,
        key.key,
        algorithms=["RS256"],
        audience=env("GOOGLE_CLIENT_ID"),
        issuer=GOOGLE_ISSUERS,
        options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        leeway=30,
    )


def signed_cookies(expires: int) -> list[str]:
    """CloudFront-Policy, -Signature and -Key-Pair-Id for a custom policy on the whole site until `expires`."""
    policy = json.dumps(
        {
            "Statement": [
                {
                    "Resource": f"https://{env('DOMAIN')}/*",
                    "Condition": {"DateLessThan": {"AWS:EpochTime": expires}},
                }
            ]
        },
        separators=(",", ":"),
    ).encode()
    signature = _private_key().sign(
        policy,
        padding.PKCS1v15(),
        hashes.SHA1(),  # nosec B303: CloudFront requires RSA-SHA1
    )
    max_age = max(0, expires - int(time.time()))
    values = (_cf_b64(policy), _cf_b64(signature), env("KEY_PAIR_ID"))
    return [_cookie(name, value, max_age) for name, value in zip(CF_COOKIES, values)]


def _deny(reason: str, message: str, email: str = "") -> dict:
    _log("deny", reason, email=email or None)
    body = (
        f"<p>{message}</p>"
        + (f"<p>You signed in as {html.escape(email)}.</p>" if email else "")
        + '<p><a href="/_auth/login?switch=1">Sign in with another account</a></p>'
    )
    # 401, not 403: CloudFront replaces 403s with the sign-in page, which would retry straight away.
    return _page(401, "Not signed in", body, [_expire(tx_cookie())])


def _read_tx(raw: str | None) -> dict | None:
    if not raw:
        return None
    try:
        tx = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    except ValueError:
        return None
    if not isinstance(tx, dict) or not all(
        isinstance(tx.get(k), str) for k in ("state", "nonce", "verifier", "rd")
    ):
        return None
    return tx


def _parse_cookies(pairs: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for pair in pairs:
        name, sep, value = pair.partition("=")
        if sep:
            out.setdefault(name.strip(), value.strip())
    return out


def _redirect_uri() -> str:
    return f"https://{env('DOMAIN')}/_auth/callback"


def _cookie(name: str, value: str, max_age: int) -> str:
    return f"{name}={value}; Max-Age={max_age}; Path=/; Secure; HttpOnly; SameSite=Lax"


def _expire(name: str) -> str:
    return f"{name}=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax"


def _redirect(location: str, cookies: list[str]) -> dict:
    return {
        "statusCode": 302,
        "headers": {"Location": location, "Cache-Control": "no-store"},
        "cookies": cookies,
        "body": "",
    }


def _page(status: int, title: str, body: str, cookies: list[str] | None = None) -> dict:
    doc = (
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{title} · {html.escape(env('SITE_TITLE'))}</title>"
        '<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem;line-height:1.5">'
        f"<h1>{title}</h1>{body}</body></html>"
    )
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
        },
        "cookies": cookies or [],
        "body": doc,
    }


def _log(outcome: str, reason: str, **fields: Any) -> None:
    print(
        json.dumps(
            {
                "outcome": outcome,
                "reason": reason,
                **{k: v for k, v in fields.items() if v is not None},
            }
        )
    )


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _cf_b64(b: bytes) -> str:
    """CloudFront's URL-safe base64: `+` `=` `/` become `-` `_` `~`."""
    return base64.b64encode(b).decode().translate(str.maketrans("+=/", "-_~"))
