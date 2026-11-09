"""PrivateStaticSite: a static site in a private S3 bucket behind CloudFront, readable only after Google sign-in.

Factored out of architecture-hub's infra (PR #44); see README.md alongside for the design, the one
console step Google still needs, and the runbooks.
"""

import html
import json
import re
from pathlib import Path
from string import Template
from typing import TypedDict

import pulumi
import pulumi_aws as aws
from components.aws.private_static_site import build
from components.aws.s3.bucket import Bucket

HERE = Path(__file__).parent

# AWS managed policies and constants
CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"
CACHING_DISABLED = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"
ALL_VIEWER_EXCEPT_HOST = "b689b0a8-53d0-40ab-baf2-68738e2966ac"
CLOUDFRONT_ZONE_ID = "Z2FDTNDATAQYW2"
GITHUB_OIDC_URL = "https://token.actions.githubusercontent.com"

S3_ORIGIN = "s3-site"
AUTH_ORIGIN = "auth"
PUBLIC_PAGES = ("signin.html", "404.html")
MAX_SESSION_HOURS = 168

NAME_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?")
# GitHub OIDC `sub`: a fixed org/repo, then anything (wildcards allowed only after the repo).
SUBJECT_RE = re.compile(r"repo:[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+:\S+")
# A lowercase DNS name. `domain` ends up in the signed cookie policy's Resource and `allowed_hd` in
# the hd check, so neither may carry wildcards or anything else.
HOST_RE = re.compile(
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}"
)


class _RequiredArgs(TypedDict):
    domain: str
    hosted_zone_id: str
    google_client_id: str
    allowed_hd: str
    cloudfront_public_key: str
    deploy_subjects: list[str]
    site_title: str


# total=False rather than NotRequired, which Pulumi's Analyzer can't read.
class PrivateStaticSiteArgs(_RequiredArgs, total=False):
    """
    Component input args.

    Fields:
    - domain: the site's hostname, e.g. policy-research.labs.climatepolicyradar.org.
    - hosted_zone_id: the Route53 zone that holds `domain`.
    - google_client_id: the Web application OAuth client, made by hand (see `oauth_setup`).
    - allowed_hd: the Google Workspace domain whose verified accounts may sign in.
    - cloudfront_public_key: PEM public half of the cookie-signing key pair; the private half
      goes only into the Secrets Manager secret.
    - deploy_subjects: GitHub OIDC `sub` patterns that may assume the deploy role, e.g.
      repo:org/repo:ref:refs/heads/main and repo:org/repo:pull_request.
    - site_title: shown on the sign-in, not-found and refusal pages.
    - session_hours: how long a sign-in lasts (1 to 168, default 12).
    """

    session_hours: int | None


def _validate(name: str, args: PrivateStaticSiteArgs) -> int:
    if not NAME_RE.fullmatch(name):
        raise ValueError(
            f"PrivateStaticSite name {name!r}: lowercase letters, digits and '-', at most 40"
        )
    for key in (
        "domain",
        "hosted_zone_id",
        "google_client_id",
        "allowed_hd",
        "cloudfront_public_key",
        "site_title",
    ):
        if not isinstance(args.get(key), str) or not args[key].strip():
            raise ValueError(f"PrivateStaticSite {name}: {key} is required")
    for key in ("domain", "allowed_hd"):
        if not HOST_RE.fullmatch(args[key]):
            raise ValueError(
                f"PrivateStaticSite {name}: {key} {args[key]!r} must be a lowercase DNS name"
            )
    subjects = args.get("deploy_subjects")
    if not isinstance(subjects, list) or not subjects:
        raise ValueError(
            f"PrivateStaticSite {name}: deploy_subjects must be a non-empty list"
        )
    for s in subjects:
        if (
            not isinstance(s, str)
            or not SUBJECT_RE.fullmatch(s)
            or "*" in s.split(":")[1]
        ):
            raise ValueError(
                f"PrivateStaticSite {name}: deploy subject {s!r} must be repo:<org>/<repo>:<...>"
            )
    hours = 12 if args.get("session_hours") is None else args["session_hours"]
    if (
        isinstance(hours, bool)
        or not isinstance(hours, int)
        or not 1 <= hours <= MAX_SESSION_HOURS
    ):
        raise ValueError(
            f"PrivateStaticSite {name}: session_hours must be a whole number from 1 to 168"
        )
    return hours


def render_page(page: str, name: str, site_title: str, allowed_hd: str) -> str:
    """A public page with the site's title, Workspace domain and sign-in loop guard key filled in."""
    return Template((HERE / "public" / page).read_text()).substitute(
        site_title=html.escape(site_title),
        allowed_hd=html.escape(allowed_hd),
        storage_key=json.dumps(f"{name}-signin-at"),
    )


def oauth_setup_steps(name: str, domain: str, allowed_hd: str) -> str:
    return (
        "Google OAuth client (console only; Google has no API for it). In a Google Cloud project owned "
        f"by the {allowed_hd} organisation: OAuth consent screen -> User type: Internal, scopes: openid, "
        f"email. Credentials -> Create OAuth client ID -> Web application, named '{name}', authorised "
        f"redirect URI https://{domain}/_auth/callback, no JavaScript origins. Put the client ID in stack "
        f"config and the client secret into the Secrets Manager secret '{name}/auth' (see the "
        "PrivateStaticSite README)."
    )


class PrivateStaticSite(pulumi.ComponentResource):
    """
    A static site in a private S3 bucket behind CloudFront signed cookies, with a small sign-in Lambda
    that admits only verified Google accounts in `allowed_hd`.

    The Google OAuth client cannot be created by API or IaC (the IAP OAuth Admin API was shut down on
    19 March 2026; google_iam_oauth_client is for Workforce Identity Federation only): make it by hand
    from the `oauth_setup` output, then fill the `auth_secret_name` secret by hand (README runbook).
    Pulumi never holds a secret.
    """

    bucket_name: pulumi.Output[str]
    """The site bucket; deploy with `aws s3 sync ... --exclude '_public/*'`."""
    distribution_id: pulumi.Output[str]
    """The CloudFront distribution, for invalidations."""
    deploy_role_arn: pulumi.Output[str]
    """The role GitHub Actions assumes (via OIDC) to deploy content."""
    auth_secret_name: pulumi.Output[str]
    """The Secrets Manager secret to fill by hand: {"google_client_secret", "cloudfront_private_key"}."""
    oauth_redirect_uri: pulumi.Output[str]
    """The redirect URI to register on the Google OAuth client."""
    url: pulumi.Output[str]
    """The site's URL."""
    oauth_setup: pulumi.Output[str]
    """The console steps for the Google OAuth client."""

    def __init__(
        self,
        name: str,
        args: PrivateStaticSiteArgs,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        super().__init__(
            "components:aws/private_static_site:PrivateStaticSite", name, None, opts
        )
        session_hours = _validate(name, args)
        domain = args["domain"]
        zone_id = args["hosted_zone_id"]
        allowed_hd = args["allowed_hd"]
        site_title = args["site_title"]
        child = pulumi.ResourceOptions(parent=self)
        tags = {
            "CPR-Created-By": "pulumi",
            "CPR-Pulumi-Stack-Name": pulumi.get_stack(),
            "CPR-Pulumi-Project-Name": pulumi.get_project(),
            "CPR-Tag": name,
            "Environment": pulumi.get_stack(),
        }

        # ----- bucket (private; CloudFront reads it through OAC) -----

        site_bucket = Bucket(
            f"{name}-site",
            args={
                "aws_s3_bucket_args": aws.s3.BucketArgs(
                    bucket=f"cpr-{name}-site", tags=tags
                )
            },
            opts=child,
        )
        bucket = site_bucket.aws_s3_bucket

        public_access_block = aws.s3.BucketPublicAccessBlock(
            f"{name}-site-public-access-block",
            bucket=bucket.id,
            block_public_acls=True,
            block_public_policy=True,
            ignore_public_acls=True,
            restrict_public_buckets=True,
            opts=child,
        )

        s3_oac = aws.cloudfront.OriginAccessControl(
            f"{name}-s3-oac",
            name=f"{name}-s3",
            origin_access_control_origin_type="s3",
            signing_behavior="always",
            signing_protocol="sigv4",
            opts=child,
        )

        # The sign-in and not-found pages, served without cookies from /_public/. The deploy role is
        # denied writes there.
        for page in PUBLIC_PAGES:
            aws.s3.BucketObjectv2(
                f"{name}-public-{page}",
                bucket=bucket.id,
                key=f"_public/{page}",
                content=render_page(page, name, site_title, allowed_hd),
                content_type="text/html; charset=utf-8",
                cache_control="no-cache",
                tags=tags,
                opts=child,
            )

        # ----- sign-in Lambda (regional, behind a Function URL only CloudFront can call) -----

        auth_secret = aws.secretsmanager.Secret(
            f"{name}-auth",
            name=f"{name}/auth",
            description='{"google_client_secret", "cloudfront_private_key"}; set by hand, see the PrivateStaticSite README',
            recovery_window_in_days=7,
            tags=tags,
            opts=child,
        )

        auth_log_group = aws.cloudwatch.LogGroup(
            f"{name}-auth-logs",
            name=f"/aws/lambda/{name}-auth",
            retention_in_days=30,
            tags=tags,
            opts=child,
        )

        auth_role = aws.iam.Role(
            f"{name}-auth",
            name=f"{name}-auth",
            assume_role_policy=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            ),
            tags=tags,
            opts=child,
        )

        aws.iam.RolePolicy(
            f"{name}-auth",
            role=auth_role.id,
            policy=pulumi.Output.all(auth_secret.arn, auth_log_group.arn).apply(
                lambda a: json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "secretsmanager:GetSecretValue",
                                "Resource": a[0],
                            },
                            {
                                "Effect": "Allow",
                                "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                                "Resource": f"{a[1]}:*",
                            },
                        ],
                    }
                )
            ),
            opts=child,
        )

        cloudfront_key = aws.cloudfront.PublicKey(
            f"{name}-cookies",
            name=f"{name}-cookies",
            # as AWS stores it, or every run replaces it
            encoded_key=args["cloudfront_public_key"].strip() + "\n",
            comment="Signs sign-in cookies",
            opts=child,
        )
        key_group = aws.cloudfront.KeyGroup(
            f"{name}-cookies",
            name=f"{name}-cookies",
            items=[cloudfront_key.id],
            opts=child,
        )

        self.auth_function = aws.lambda_.Function(
            f"{name}-auth",
            name=f"{name}-auth",
            runtime=build.RUNTIME,
            architectures=["arm64"],
            handler="handler.handler",
            code=pulumi.FileArchive(str(build.build())),
            role=auth_role.arn,
            memory_size=256,
            timeout=10,
            environment=aws.lambda_.FunctionEnvironmentArgs(
                variables={
                    "DOMAIN": domain,
                    "ALLOWED_HD": allowed_hd,
                    "GOOGLE_CLIENT_ID": args["google_client_id"],
                    "SECRET_ID": auth_secret.arn,
                    "KEY_PAIR_ID": cloudfront_key.id,
                    "SESSION_HOURS": str(session_hours),
                    "TX_COOKIE": f"__Host-{name}-auth",
                    "SITE_TITLE": site_title,
                }
            ),
            tags=tags,
            opts=pulumi.ResourceOptions(parent=self, depends_on=[auth_log_group]),
        )

        auth_url = aws.lambda_.FunctionUrl(
            f"{name}-auth",
            function_name=self.auth_function.name,
            authorization_type="AWS_IAM",
            opts=child,
        )

        lambda_oac = aws.cloudfront.OriginAccessControl(
            f"{name}-lambda-oac",
            name=f"{name}-lambda",
            origin_access_control_origin_type="lambda",
            signing_behavior="always",
            signing_protocol="sigv4",
            opts=child,
        )

        # ----- certificate (us-east-1, as CloudFront requires) and CloudFront -----

        us_east_1 = aws.Provider(f"{name}-us-east-1", region="us-east-1", opts=child)

        certificate = aws.acm.Certificate(
            f"{name}-cert",
            domain_name=domain,
            validation_method="DNS",
            tags=tags,
            opts=pulumi.ResourceOptions(parent=self, provider=us_east_1),
        )

        validation_record = aws.route53.Record(
            f"{name}-cert-validation",
            zone_id=zone_id,
            name=certificate.domain_validation_options[0].resource_record_name,
            type=certificate.domain_validation_options[0].resource_record_type,
            records=[certificate.domain_validation_options[0].resource_record_value],
            ttl=300,
            allow_overwrite=True,
            opts=child,
        )

        certificate_validation = aws.acm.CertificateValidation(
            f"{name}-cert",
            certificate_arn=certificate.arn,
            validation_record_fqdns=[validation_record.fqdn],
            opts=pulumi.ResourceOptions(parent=self, provider=us_east_1),
        )

        dir_index = aws.cloudfront.Function(
            f"{name}-dir-index",
            name=f"{name}-dir-index",
            runtime="cloudfront-js-2.0",
            code=(HERE / "dir-index.js").read_text(),
            comment="/dir/ serves dir/index.html; /dir redirects to /dir/",
            publish=True,
            opts=child,
        )

        self.distribution = aws.cloudfront.Distribution(
            f"{name}-site",
            enabled=True,
            is_ipv6_enabled=True,
            http_version="http2and3",
            price_class="PriceClass_100",
            default_root_object="index.html",
            aliases=[domain],
            comment=f"{site_title}: {domain}, behind Google sign-in"[:128],
            origins=[
                aws.cloudfront.DistributionOriginArgs(
                    origin_id=S3_ORIGIN,
                    domain_name=bucket.bucket_regional_domain_name,
                    origin_access_control_id=s3_oac.id,
                ),
                aws.cloudfront.DistributionOriginArgs(
                    origin_id=AUTH_ORIGIN,
                    domain_name=auth_url.function_url.apply(
                        lambda u: u.removeprefix("https://").rstrip("/")
                    ),
                    origin_access_control_id=lambda_oac.id,
                    custom_origin_config=aws.cloudfront.DistributionOriginCustomOriginConfigArgs(
                        http_port=80,
                        https_port=443,
                        origin_protocol_policy="https-only",
                        origin_ssl_protocols=["TLSv1.2"],
                    ),
                ),
            ],
            # Everything else needs valid signed cookies; CloudFront checks them itself.
            default_cache_behavior=aws.cloudfront.DistributionDefaultCacheBehaviorArgs(
                target_origin_id=S3_ORIGIN,
                allowed_methods=["GET", "HEAD"],
                cached_methods=["GET", "HEAD"],
                viewer_protocol_policy="redirect-to-https",
                cache_policy_id=CACHING_OPTIMIZED,
                compress=True,
                trusted_key_groups=[key_group.id],
                function_associations=[
                    aws.cloudfront.DistributionDefaultCacheBehaviorFunctionAssociationArgs(
                        event_type="viewer-request", function_arn=dir_index.arn
                    )
                ],
            ),
            ordered_cache_behaviors=[
                # Sign-in itself: no cookies needed, never cached, all query strings and cookies forwarded.
                aws.cloudfront.DistributionOrderedCacheBehaviorArgs(
                    path_pattern="/_auth/*",
                    target_origin_id=AUTH_ORIGIN,
                    allowed_methods=["GET", "HEAD"],
                    cached_methods=["GET", "HEAD"],
                    viewer_protocol_policy="redirect-to-https",
                    cache_policy_id=CACHING_DISABLED,
                    origin_request_policy_id=ALL_VIEWER_EXCEPT_HOST,
                ),
                aws.cloudfront.DistributionOrderedCacheBehaviorArgs(
                    path_pattern="/_public/*",
                    target_origin_id=S3_ORIGIN,
                    allowed_methods=["GET", "HEAD"],
                    cached_methods=["GET", "HEAD"],
                    viewer_protocol_policy="redirect-to-https",
                    cache_policy_id=CACHING_OPTIMIZED,
                    compress=True,
                ),
            ],
            custom_error_responses=[
                # No or bad cookies: the sign-in page, with the asked-for URL left in the address bar.
                aws.cloudfront.DistributionCustomErrorResponseArgs(
                    error_code=403,
                    response_code=403,
                    response_page_path="/_public/signin.html",
                    error_caching_min_ttl=0,
                ),
                # Signed in, but no such object (CloudFront may list the bucket, so S3 says 404, not 403).
                aws.cloudfront.DistributionCustomErrorResponseArgs(
                    error_code=404,
                    response_code=404,
                    response_page_path="/_public/404.html",
                    error_caching_min_ttl=60,
                ),
            ],
            viewer_certificate=aws.cloudfront.DistributionViewerCertificateArgs(
                acm_certificate_arn=certificate_validation.certificate_arn,
                ssl_support_method="sni-only",
                minimum_protocol_version="TLSv1.2_2021",
            ),
            restrictions=aws.cloudfront.DistributionRestrictionsArgs(
                geo_restriction=aws.cloudfront.DistributionRestrictionsGeoRestrictionArgs(
                    restriction_type="none"
                )
            ),
            tags=tags,
            opts=child,
        )
        distribution = self.distribution

        aws.s3.BucketPolicy(
            f"{name}-site",
            bucket=bucket.id,
            policy=pulumi.Output.all(bucket.arn, distribution.arn).apply(
                lambda a: json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "CloudFrontReadsAndLists",
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudfront.amazonaws.com"},
                                "Action": ["s3:GetObject", "s3:ListBucket"],
                                "Resource": [a[0], f"{a[0]}/*"],
                                "Condition": {"StringEquals": {"AWS:SourceArn": a[1]}},
                            }
                        ],
                    }
                )
            ),
            opts=pulumi.ResourceOptions(parent=self, depends_on=[public_access_block]),
        )

        # CloudFront through OAC needs both permissions on a Function URL.
        aws.lambda_.Permission(
            f"{name}-auth-url",
            function=self.auth_function.name,
            action="lambda:InvokeFunctionUrl",
            principal="cloudfront.amazonaws.com",
            source_arn=distribution.arn,
            function_url_auth_type="AWS_IAM",
            opts=child,
        )
        aws.lambda_.Permission(
            f"{name}-auth-invoke",
            function=self.auth_function.name,
            action="lambda:InvokeFunction",
            principal="cloudfront.amazonaws.com",
            source_arn=distribution.arn,
            invoked_via_function_url=True,
            opts=child,
        )

        for record_type in ("A", "AAAA"):
            aws.route53.Record(
                f"{name}-{record_type.lower()}",
                zone_id=zone_id,
                name=domain,
                type=record_type,
                aliases=[
                    aws.route53.RecordAliasArgs(
                        name=distribution.domain_name,
                        zone_id=CLOUDFRONT_ZONE_ID,
                        evaluate_target_health=False,
                    )
                ],
                opts=child,
            )

        # ----- deploy role: GitHub Actions on deploy_subjects only, site content only -----

        github_oidc = aws.iam.get_open_id_connect_provider_output(
            url=GITHUB_OIDC_URL, opts=pulumi.InvokeOutputOptions(parent=self)
        )

        deploy_role = aws.iam.Role(
            f"{name}-deploy",
            name=f"{name}-deploy",
            assume_role_policy=github_oidc.arn.apply(
                lambda arn: json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Federated": arn},
                                "Action": "sts:AssumeRoleWithWebIdentity",
                                "Condition": {
                                    "StringEquals": {
                                        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
                                    },
                                    "StringLike": {
                                        "token.actions.githubusercontent.com:sub": list(
                                            args["deploy_subjects"]
                                        )
                                    },
                                },
                            }
                        ],
                    }
                )
            ),
            tags=tags,
            opts=child,
        )

        aws.iam.RolePolicy(
            f"{name}-deploy",
            role=deploy_role.id,
            policy=pulumi.Output.all(bucket.arn, distribution.arn).apply(
                lambda a: json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:ListBucket",
                                "Resource": a[0],
                            },
                            {
                                "Effect": "Allow",
                                "Action": ["s3:PutObject", "s3:DeleteObject"],
                                "Resource": f"{a[0]}/*",
                            },
                            {
                                "Effect": "Deny",
                                "Action": ["s3:PutObject", "s3:DeleteObject"],
                                "Resource": f"{a[0]}/_public/*",
                            },
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "cloudfront:CreateInvalidation",
                                    "cloudfront:GetInvalidation",
                                ],
                                "Resource": a[1],
                            },
                        ],
                    }
                )
            ),
            opts=child,
        )

        # ----- outputs -----

        self.bucket_name = bucket.bucket
        self.distribution_id = distribution.id
        self.deploy_role_arn = deploy_role.arn
        self.auth_secret_name = auth_secret.name
        self.oauth_redirect_uri = pulumi.Output.from_input(
            f"https://{domain}/_auth/callback"
        )
        self.url = pulumi.Output.from_input(f"https://{domain}")
        self.oauth_setup = pulumi.Output.from_input(
            oauth_setup_steps(name, domain, allowed_hd)
        )

        self.register_outputs(
            {
                "bucket_name": self.bucket_name,
                "distribution_id": self.distribution_id,
                "deploy_role_arn": self.deploy_role_arn,
                "auth_secret_name": self.auth_secret_name,
                "oauth_redirect_uri": self.oauth_redirect_uri,
                "url": self.url,
                "oauth_setup": self.oauth_setup,
            }
        )
