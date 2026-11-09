# PrivateStaticSite

A static site in a private S3 bucket behind CloudFront, readable only by
verified Google accounts in one Workspace domain. Factored out of
architecture-hub PR #44 (its `infra/`); the design and security properties are
unchanged.

```text
Browser ─GET /x──────────────▶ CloudFront [needs signed cookies] ──▶ S3 (private, OAC)
   no or bad cookies ◀─ 403: /_public/signin.html, which sends you to /_auth/login?rd=/x
Browser ─/_auth/login?rd=/x──▶ CloudFront [/_auth/*: no cookies, no cache] ──▶ auth Lambda (Function URL, OAC)
   ◀─ 302 to Google (state, nonce and PKCE verifier in a 10-minute __Host- cookie)
Google ─/_auth/callback?code─▶ auth Lambda: exchange the code, verify the id_token (JWKS, aud, iss, exp,
   nonce), require email_verified and hd == allowed_hd, sign a session_hours CloudFront policy
   ◀─ Set-Cookie CloudFront-Policy / -Signature / -Key-Pair-Id, 302 to /x
Browser ─GET /x + cookies────▶ CloudFront checks the signature itself ──▶ S3
```

- **Static pages never depend on the Lambda.** If Google or the Lambda is down,
  signed-in people carry on; only new sign-ins fail. Refusals are 401 (a 403
  would loop back to the sign-in page).
- **No secret is in Pulumi.** The component creates the Secrets Manager secret
  `<name>/auth` empty; the Google client secret and the CloudFront private key
  go in by hand. The Lambda may only `GetSecretValue` that secret.
- **Cookies are host-only** (no `Domain=`), `Secure; HttpOnly; SameSite=Lax`.
  Never widen them to a parent domain: other teams' apps live there.
- **Deploys can't touch sign-in.** The GitHub OIDC deploy role
  (`deploy_subjects` only) may list the bucket, put and delete objects, and
  invalidate the distribution, but is denied on `_public/*`.

## Usage

```python
from components.aws.private_static_site import PrivateStaticSite, PrivateStaticSiteArgs

site = PrivateStaticSite(
    "policy-research-labs",  # lowercase, digits and '-'; names the bucket (cpr-<name>-site), secret, roles
    PrivateStaticSiteArgs(
        domain="policy-research.labs.climatepolicyradar.org",
        hosted_zone_id="Z003590321BD9G50CXG1I",
        google_client_id=cfg.require("google_client_id"),
        allowed_hd="climatepolicyradar.org",
        cloudfront_public_key=cfg.require("cloudfront_public_key"),
        deploy_subjects=[
            "repo:climatepolicyradar/internal-policy-research:ref:refs/heads/main",
            "repo:climatepolicyradar/internal-policy-research:pull_request",
        ],
        site_title="Policy research",
        session_hours=12,  # optional, 1 to 168
    ),
)
for output in ("url", "bucket_name", "distribution_id", "deploy_role_arn", "auth_secret_name",
               "oauth_redirect_uri", "oauth_setup"):
    pulumi.export(output, getattr(site, output))
```

`deploy_subjects` are matched with `StringLike` against the token's `sub`; the
org and repo must be literal. The stack's default AWS provider sets the region
for everything except the certificate, which the component makes in us-east-1
with its own provider (from the ambient credentials).

`pulumi up` and `preview` bundle the sign-in Lambda (`build.py`:
`auth/handler.py` plus `auth/requirements.txt` as arm64 wheels), so they need
`uv` on `PATH` and PyPI access. The bundle is cached under
`~/.cache/cpr-components/private-static-site/`.

## Set up a site (once)

You need the target AWS profile, Pulumi Cloud access and `uv`.

1. **Google OAuth client, by hand.** Google has no API for it: the IAP OAuth
   Admin API (`google_iap_brand`/`google_iap_client`) was shut down on 19 March
   2026 and only ever made IAP-locked clients, and `google_iam_oauth_client` is
   for Workforce Identity Federation only. The `oauth_setup` output prints these
   steps with the site's values. In a Google Cloud project owned by the
   `allowed_hd` organisation:
   - OAuth consent screen: **User type: Internal**, so Google itself refuses
     other accounts. Scopes: `openid`, `email`.
   - Credentials → Create OAuth client ID → **Web application**, named after the
     site. Authorised redirect URI: `https://<domain>/_auth/callback` (the
     `oauth_redirect_uri` output). No JavaScript origins.
   - Keep the client ID and secret for the next steps. One client per site, so
     rotation and audit stay separate.
2. **CloudFront key pair**, made outside Pulumi so the private half never
   reaches its state, and in memory (`/dev/shm`) so it never reaches disk:

   ```sh
   umask 077 && mkdir -p /dev/shm/site-keys
   openssl genrsa -out /dev/shm/site-keys/cf-private.pem 2048
   openssl rsa -pubout -in /dev/shm/site-keys/cf-private.pem -out /dev/shm/site-keys/cf-public.pem
   ```

3. **Stack config.** The client ID and public key aren't secret; commit them in
   `Pulumi.<stack>.yaml`.

   ```sh
   pulumi config set google_client_id <client id>
   pulumi config set cloudfront_public_key -- "$(cat /dev/shm/site-keys/cf-public.pem)"
   ```

4. **Create everything**: `pulumi up`. The certificate waits for DNS validation;
   CloudFront takes a few minutes.
5. **Fill the secret** from your own terminal, so the client secret stays out of
   shell history, the process list and any agent session, then destroy the local
   copies:

   ```sh
   read -rs CLIENT_SECRET   # paste it, then Enter; nothing is echoed
   jq -n --arg s "$CLIENT_SECRET" --rawfile k /dev/shm/site-keys/cf-private.pem \
     '{google_client_secret: $s, cloudfront_private_key: $k}' > /dev/shm/site-keys/auth.json
   aws secretsmanager put-secret-value \
     --secret-id "$(pulumi stack output auth_secret_name)" --secret-string file:///dev/shm/site-keys/auth.json
   shred -u /dev/shm/site-keys/*; rmdir /dev/shm/site-keys; unset CLIENT_SECRET
   ```

   Delete any `client_secret_*.json` downloaded from Google too. Neither secret
   needs a backup: both can be made again (see rotation).

## Verify

`check-access.sh` (next to this README) must pass; with the secret name it also
fails while the secret is empty:

```sh
"$(uv run python -c 'import components.aws.private_static_site as m, pathlib; print(pathlib.Path(m.__file__).parent)')/check-access.sh" \
  <domain> "$(pulumi stack output bucket_name)" <allowed_hd> "$(pulumi stack output auth_secret_name)" [region]
```

Then by hand, in a private window: an `allowed_hd` account signs in and lands on
the page it asked for; a personal account is refused (401, no `CloudFront-*`
cookies); `/_auth/logout` signs you out; the log group `/aws/lambda/<name>-auth`
has one line per attempt, with an email only on refusals.

## Operate

**Deploying content.** Assume `deploy_role_arn` from GitHub Actions, then
`aws s3 sync <dir> s3://<bucket_name> --delete --exclude '_public/*'` and
invalidate `/*`.

**Revoking someone.** Suspend them in Google Workspace: they can't sign in again
and their cookies run out within `session_hours`. To cut everyone off now,
rotate the CloudFront key.

**Rotating the CloudFront key** (also the emergency "sign everyone out"): make a
new pair (set-up step 2); `pulumi config set cloudfront_public_key ...` and
`pulumi up`, which replaces the key, so every cookie stops working and the
Lambda's `KEY_PAIR_ID` moves; put the new private key into the secret (step 5,
keeping the client secret); force a cold start so the Lambda reads it. Sign-ins
fail between `pulumi up` and the cold start, so do them together.

```sh
aws lambda update-function-configuration --function-name <name>-auth \
  --description "rotated $(date -I)"
```

**Rotating the Google client secret.** Add a new secret on the OAuth client, put
it into the AWS secret (keep the private key), force a cold start as above,
check a sign-in, then delete the old one in Google.

**Cost.** About $1 a month per site (the secret); CloudFront and Lambda stay in
free tiers at internal volumes.

## Migrating architecture-hub onto the component

PR #44's resources and the component's children have the same types and logical
names when the component is named `architecture-hub-labs` (its
`{project}-{stack}`); only their parent changes. So alias every AWS resource
(and the us-east-1 provider) to its old root-level URN:

```python
def adopt(args: pulumi.ResourceTransformationArgs):
    if not isinstance(args.resource, pulumi.CustomResource):
        return None  # the component wrappers are new
    alias = pulumi.ResourceOptions(aliases=[pulumi.Alias(parent=pulumi.ROOT_STACK_RESOURCE)])
    return pulumi.ResourceTransformationResult(args.props, pulumi.ResourceOptions.merge(args.opts, alias))

site = PrivateStaticSite(
    "architecture-hub-labs",
    PrivateStaticSiteArgs(
        ...,  # domain, zone, client ID, hd, public key from the existing config
        deploy_subjects=["repo:climatepolicyradar/architecture-hub:ref:refs/heads/main"],
        site_title="Architecture hub",
    ),
    opts=pulumi.ResourceOptions(transformations=[adopt]),
)
```

`test_architecture_hub_migration_transform_covers_every_pr44_resource` checks
the transform sees exactly PR #44's 27 resources. `pulumi preview` must then
show no creates, deletes or replaces, only in-place updates: the bucket gains
versioning, SSE and the 90-day noncurrent-version rule; the public pages, Lambda
code and env (`TX_COOKIE`, `SITE_TITLE`), distribution comment and deploy trust
policy (`StringLike`) change. Sign-ins in flight during the update fail once
(the transaction cookie is renamed). Stack outputs are renamed (`bucket` →
`bucket_name`, `auth_secret` → `auth_secret_name`), so update the deploy
workflow and `check-access.sh` arguments. Keep the transformation until every
stack has run `pulumi up` once.
