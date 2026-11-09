import json

import pulumi
import pytest
from components.aws.private_static_site import PrivateStaticSite, PrivateStaticSiteArgs
from components.aws.private_static_site import build as build_module
from components.aws.private_static_site.private_static_site import (
    CACHING_DISABLED,
    PUBLIC_PAGES,
)
from pulumi.provider.experimental.analyzer import Analyzer

DOMAIN = "site.example.org"
SUBJECTS = [
    "repo:climatepolicyradar/internal-policy-research:ref:refs/heads/main",
    "repo:climatepolicyradar/internal-policy-research:pull_request",
]
OIDC_ARN = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"


class SiteMocks(pulumi.runtime.Mocks):
    """Inputs back as outputs, plus the computed attributes the component reads."""

    def __init__(self) -> None:
        self.resources: list[pulumi.runtime.MockResourceArgs] = []

    def new_resource(self, args: pulumi.runtime.MockResourceArgs) -> tuple[str, dict]:
        self.resources.append(args)
        out = dict(args.inputs)
        arn = f"arn:aws:mock:::{args.name}"
        if args.typ == "aws:s3/bucket:Bucket":
            out |= {
                "arn": f"arn:aws:s3:::{out['bucket']}",
                "bucketRegionalDomainName": f"{out['bucket']}.s3.amazonaws.com",
            }
        elif args.typ == "aws:acm/certificate:Certificate":
            out |= {
                "arn": arn,
                "domainValidationOptions": [
                    {
                        "domainName": DOMAIN,
                        "resourceRecordName": f"_x.{DOMAIN}.",
                        "resourceRecordType": "CNAME",
                        "resourceRecordValue": "_y.acm-validations.aws.",
                    }
                ],
            }
        elif args.typ == "aws:lambda/functionUrl:FunctionUrl":
            out["functionUrl"] = "https://abc.lambda-url.eu-west-1.on.aws/"
        elif args.typ == "aws:cloudfront/distribution:Distribution":
            out |= {"arn": arn, "domainName": "d123.cloudfront.net"}
        elif args.typ == "aws:route53/record:Record":
            out["fqdn"] = out["name"]
        else:
            out.setdefault("arn", arn)
        return f"{args.name}_id", out

    def call(self, args: pulumi.runtime.MockCallArgs) -> tuple[dict, list]:
        if args.token == "aws:iam/getOpenIdConnectProvider:getOpenIdConnectProvider":
            return {"arn": OIDC_ARN, "url": "token.actions.githubusercontent.com"}, []
        return {}, []

    def of(self, typ: str) -> list[pulumi.runtime.MockResourceArgs]:
        return [r for r in self.resources if r.typ == typ]

    def one(self, typ: str, name: str) -> dict:
        (r,) = [r for r in self.of(typ) if r.name == name]
        return r.inputs


@pytest.fixture
def pulumi_mocks(monkeypatch, tmp_path):
    # Overrides the conftest fixture; no uv/PyPI in unit tests.
    (tmp_path / "handler.py").write_text("")
    monkeypatch.setattr(build_module, "build", lambda: tmp_path)
    mocks = SiteMocks()
    pulumi.runtime.set_mocks(mocks, preview=False)
    return mocks


def site_args(**overrides) -> PrivateStaticSiteArgs:
    return (
        PrivateStaticSiteArgs(
            domain=DOMAIN,
            hosted_zone_id="Z123",
            google_client_id="client-123.apps.googleusercontent.com",
            allowed_hd="climatepolicyradar.org",
            cloudfront_public_key="-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----",
            deploy_subjects=SUBJECTS,
            site_title="Policy <research>",
        )
        | overrides
    )


OUTPUTS = (
    "bucket_name",
    "distribution_id",
    "deploy_role_arn",
    "auth_secret_name",
    "oauth_redirect_uri",
    "url",
    "oauth_setup",
)


def deploy(
    mocks: SiteMocks,
    name: str = "test",
    opts: pulumi.ResourceOptions | None = None,
    **overrides,
) -> dict:
    """Register a site under the mocks, wait for every resource, and return its resolved outputs."""
    resolved: dict = {}

    @pulumi.runtime.test
    def run():
        site = PrivateStaticSite(name, site_args(**overrides), opts)
        return pulumi.Output.all(*(getattr(site, o) for o in OUTPUTS)).apply(
            lambda values: resolved.update(zip(OUTPUTS, values))
        )

    run()  # returns once every registration has finished
    return resolved


def test_bucket_is_private_and_only_cloudfront_reads_it(pulumi_mocks):
    deploy(pulumi_mocks)

    (bucket,) = pulumi_mocks.of("aws:s3/bucket:Bucket")
    assert bucket.inputs["bucket"] == "cpr-test-site"
    assert bucket.inputs.get("acl") is None
    assert bucket.inputs["versioning"]["enabled"] is True
    assert (
        bucket.inputs["serverSideEncryptionConfiguration"]["rule"][
            "applyServerSideEncryptionByDefault"
        ]["sseAlgorithm"]
        == "AES256"
    )

    (pab,) = pulumi_mocks.of("aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock")
    for k in (
        "blockPublicAcls",
        "blockPublicPolicy",
        "ignorePublicAcls",
        "restrictPublicBuckets",
    ):
        assert pab.inputs[k] is True

    (policy,) = pulumi_mocks.of("aws:s3/bucketPolicy:BucketPolicy")
    (stmt,) = json.loads(policy.inputs["policy"])["Statement"]
    assert stmt["Effect"] == "Allow"
    assert stmt["Principal"] == {"Service": "cloudfront.amazonaws.com"}
    assert stmt["Condition"] == {
        "StringEquals": {"AWS:SourceArn": "arn:aws:mock:::test-site"}
    }

    (s3_oac,) = [
        r
        for r in pulumi_mocks.of(
            "aws:cloudfront/originAccessControl:OriginAccessControl"
        )
        if r.inputs["originAccessControlOriginType"] == "s3"
    ]
    assert s3_oac.inputs["signingBehavior"] == "always"


def test_default_behaviour_requires_signed_cookies(pulumi_mocks):
    deploy(pulumi_mocks)

    (dist,) = pulumi_mocks.of("aws:cloudfront/distribution:Distribution")
    default = dist.inputs["defaultCacheBehavior"]
    assert default["targetOriginId"] == "s3-site"
    assert default["trustedKeyGroups"] == ["test-cookies_id"]
    assert default["viewerProtocolPolicy"] == "redirect-to-https"
    assert pulumi_mocks.one("aws:cloudfront/keyGroup:KeyGroup", "test-cookies")[
        "items"
    ] == ["test-cookies_id"]
    assert dist.inputs["aliases"] == [DOMAIN]
    assert dist.inputs["comment"].startswith("Policy <research>: ")
    assert dist.inputs["viewerCertificate"]["minimumProtocolVersion"] == "TLSv1.2_2021"

    errors = {
        e["errorCode"]: e["responsePagePath"]
        for e in dist.inputs["customErrorResponses"]
    }
    assert errors == {403: "/_public/signin.html", 404: "/_public/404.html"}


def test_auth_and_public_behaviours(pulumi_mocks):
    deploy(pulumi_mocks)

    (dist,) = pulumi_mocks.of("aws:cloudfront/distribution:Distribution")
    behaviours = {b["pathPattern"]: b for b in dist.inputs["orderedCacheBehaviors"]}
    assert set(behaviours) == {"/_auth/*", "/_public/*"}

    auth = behaviours["/_auth/*"]
    assert auth["targetOriginId"] == "auth"
    assert auth["cachePolicyId"] == CACHING_DISABLED
    assert not auth.get("trustedKeyGroups")
    assert behaviours["/_public/*"]["targetOriginId"] == "s3-site"
    assert not behaviours["/_public/*"].get("trustedKeyGroups")

    origins = {o["originId"]: o for o in dist.inputs["origins"]}
    assert origins["auth"]["domainName"] == "abc.lambda-url.eu-west-1.on.aws"
    assert origins["auth"]["customOriginConfig"]["originProtocolPolicy"] == "https-only"

    (url,) = pulumi_mocks.of("aws:lambda/functionUrl:FunctionUrl")
    assert url.inputs["authorizationType"] == "AWS_IAM"
    perms = {
        p.inputs["action"]: p.inputs
        for p in pulumi_mocks.of("aws:lambda/permission:Permission")
    }
    assert perms["lambda:InvokeFunctionUrl"]["functionUrlAuthType"] == "AWS_IAM"
    assert perms["lambda:InvokeFunction"]["invokedViaFunctionUrl"] is True
    assert all(
        p["principal"] == "cloudfront.amazonaws.com"
        and p["sourceArn"] == "arn:aws:mock:::test-site"
        for p in perms.values()
    )

    pages = {
        r.inputs["key"]: r.inputs
        for r in pulumi_mocks.of("aws:s3/bucketObjectv2:BucketObjectv2")
    }
    assert set(pages) == {f"_public/{p}" for p in PUBLIC_PAGES}
    signin = pages["_public/signin.html"]["content"]
    assert "<title>Sign in · Policy &lt;research&gt;</title>" in signin
    assert 'sessionStorage.getItem("test-signin-at")' in signin
    assert "climatepolicyradar.org Google account" in signin
    assert "$" not in signin + pages["_public/404.html"]["content"]


def test_deploy_role_uses_every_subject_and_cannot_touch_public(pulumi_mocks):
    deploy(pulumi_mocks)

    trust = json.loads(
        pulumi_mocks.one("aws:iam/role:Role", "test-deploy")["assumeRolePolicy"]
    )
    (stmt,) = trust["Statement"]
    assert stmt["Principal"] == {"Federated": OIDC_ARN}
    assert stmt["Condition"]["StringEquals"] == {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
    }
    assert stmt["Condition"]["StringLike"] == {
        "token.actions.githubusercontent.com:sub": SUBJECTS
    }

    (policy,) = [
        r.inputs
        for r in pulumi_mocks.of("aws:iam/rolePolicy:RolePolicy")
        if r.name == "test-deploy"
    ]
    statements = json.loads(policy["policy"])["Statement"]
    (deny,) = [s for s in statements if s["Effect"] == "Deny"]
    assert deny == {
        "Effect": "Deny",
        "Action": ["s3:PutObject", "s3:DeleteObject"],
        "Resource": "arn:aws:s3:::cpr-test-site/_public/*",
    }
    allowed = {
        a
        for s in statements
        if s["Effect"] == "Allow"
        for a in ([s["Action"]] if isinstance(s["Action"], str) else s["Action"])
    }
    assert allowed == {
        "s3:ListBucket",
        "s3:PutObject",
        "s3:DeleteObject",
        "cloudfront:CreateInvalidation",
        "cloudfront:GetInvalidation",
    }


def test_auth_lambda_reads_only_its_secret(pulumi_mocks):
    deploy(pulumi_mocks)

    (policy,) = [
        r.inputs
        for r in pulumi_mocks.of("aws:iam/rolePolicy:RolePolicy")
        if r.name == "test-auth"
    ]
    statements = json.loads(policy["policy"])["Statement"]
    assert statements[0] == {
        "Effect": "Allow",
        "Action": "secretsmanager:GetSecretValue",
        "Resource": "arn:aws:mock:::test-auth",
    }
    assert all(
        s["Action"] != "*" and "secretsmanager:*" not in s["Action"] for s in statements
    )

    secret = pulumi_mocks.one("aws:secretsmanager/secret:Secret", "test-auth")
    assert secret["name"] == "test/auth"
    assert not pulumi_mocks.of("aws:secretsmanager/secretVersion:SecretVersion")


def test_session_hours_and_names_reach_the_lambda(pulumi_mocks):
    deploy(pulumi_mocks, session_hours=3)

    fn = pulumi_mocks.one("aws:lambda/function:Function", "test-auth")
    env = fn["environment"]["variables"]
    assert env["SESSION_HOURS"] == "3"
    assert env["TX_COOKIE"] == "__Host-test-auth"
    assert env["SITE_TITLE"] == "Policy <research>"
    assert env["DOMAIN"] == DOMAIN and env["ALLOWED_HD"] == "climatepolicyradar.org"
    assert env["SECRET_ID"] == "arn:aws:mock:::test-auth"
    assert env["KEY_PAIR_ID"] == "test-cookies_id"
    assert fn["architectures"] == ["arm64"] and fn["runtime"] == build_module.RUNTIME


def test_session_hours_defaults_to_12(pulumi_mocks):
    deploy(pulumi_mocks)

    assert (
        pulumi_mocks.one("aws:lambda/function:Function", "test-auth")["environment"][
            "variables"
        ]["SESSION_HOURS"]
        == "12"
    )


def test_certificate_in_us_east_1_and_dns_aliases(pulumi_mocks):
    deploy(pulumi_mocks)

    (provider,) = pulumi_mocks.of("pulumi:providers:aws")
    assert provider.inputs["region"] == "us-east-1"
    (cert,) = pulumi_mocks.of("aws:acm/certificate:Certificate")
    assert cert.provider and "test-us-east-1" in cert.provider
    assert cert.inputs["validationMethod"] == "DNS"
    records = {
        r.inputs["type"]: r.inputs
        for r in pulumi_mocks.of("aws:route53/record:Record")
        if r.name in ("test-a", "test-aaaa")
    }
    assert set(records) == {"A", "AAAA"}
    for r in records.values():
        assert r["aliases"][0]["name"] == "d123.cloudfront.net"


def test_outputs(pulumi_mocks):
    out = deploy(pulumi_mocks)
    assert out["bucket_name"] == "cpr-test-site"
    assert out["distribution_id"] == "test-site_id"
    assert out["deploy_role_arn"] == "arn:aws:mock:::test-deploy"
    assert out["auth_secret_name"] == "test/auth"
    assert out["oauth_redirect_uri"] == f"https://{DOMAIN}/_auth/callback"
    assert out["url"] == f"https://{DOMAIN}"
    setup = out["oauth_setup"]
    assert (
        "Internal" in setup and "openid" in setup and out["oauth_redirect_uri"] in setup
    )


@pytest.mark.parametrize(
    "name, overrides",
    [
        ("Bad_Name", {}),
        ("test", {"deploy_subjects": []}),
        (
            "test",
            {"deploy_subjects": ["repo:climatepolicyradar/*:ref:refs/heads/main"]},
        ),
        ("test", {"deploy_subjects": ["*"]}),
        ("test", {"session_hours": 0}),
        ("test", {"session_hours": 169}),
        ("test", {"site_title": ""}),
        ("test", {"domain": "*.example.org"}),
        ("test", {"domain": "Site.Example.org"}),
        ("test", {"allowed_hd": "*"}),
        ("test", {"allowed_hd": "climatepolicyradar.org "}),
    ],
)
def test_bad_args_fail_loudly(pulumi_mocks, name, overrides):
    with pytest.raises(ValueError):
        PrivateStaticSite(name, site_args(**overrides))


def test_analyze_private_static_site_component():
    Analyzer(name="test").analyze_component(PrivateStaticSite)


# Every resource in architecture-hub PR #44's infra/__main__.py, as (type, logical name) with
# NAME = architecture-hub-labs. The README's migration relies on the component keeping these.
ARCH_HUB = "architecture-hub-labs"
PR44_RESOURCES = {
    ("aws:s3/bucket:Bucket", f"{ARCH_HUB}-site"),
    (
        "aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock",
        f"{ARCH_HUB}-site-public-access-block",
    ),
    ("aws:cloudfront/originAccessControl:OriginAccessControl", f"{ARCH_HUB}-s3-oac"),
    ("aws:s3/bucketObjectv2:BucketObjectv2", f"{ARCH_HUB}-public-signin.html"),
    ("aws:s3/bucketObjectv2:BucketObjectv2", f"{ARCH_HUB}-public-404.html"),
    ("aws:secretsmanager/secret:Secret", f"{ARCH_HUB}-auth"),
    ("aws:cloudwatch/logGroup:LogGroup", f"{ARCH_HUB}-auth-logs"),
    ("aws:iam/role:Role", f"{ARCH_HUB}-auth"),
    ("aws:iam/rolePolicy:RolePolicy", f"{ARCH_HUB}-auth"),
    ("aws:cloudfront/publicKey:PublicKey", f"{ARCH_HUB}-cookies"),
    ("aws:cloudfront/keyGroup:KeyGroup", f"{ARCH_HUB}-cookies"),
    ("aws:lambda/function:Function", f"{ARCH_HUB}-auth"),
    ("aws:lambda/functionUrl:FunctionUrl", f"{ARCH_HUB}-auth"),
    (
        "aws:cloudfront/originAccessControl:OriginAccessControl",
        f"{ARCH_HUB}-lambda-oac",
    ),
    ("pulumi:providers:aws", f"{ARCH_HUB}-us-east-1"),
    ("aws:acm/certificate:Certificate", f"{ARCH_HUB}-cert"),
    ("aws:route53/record:Record", f"{ARCH_HUB}-cert-validation"),
    ("aws:acm/certificateValidation:CertificateValidation", f"{ARCH_HUB}-cert"),
    ("aws:cloudfront/function:Function", f"{ARCH_HUB}-dir-index"),
    ("aws:cloudfront/distribution:Distribution", f"{ARCH_HUB}-site"),
    ("aws:s3/bucketPolicy:BucketPolicy", f"{ARCH_HUB}-site"),
    ("aws:lambda/permission:Permission", f"{ARCH_HUB}-auth-url"),
    ("aws:lambda/permission:Permission", f"{ARCH_HUB}-auth-invoke"),
    ("aws:route53/record:Record", f"{ARCH_HUB}-a"),
    ("aws:route53/record:Record", f"{ARCH_HUB}-aaaa"),
    ("aws:iam/role:Role", f"{ARCH_HUB}-deploy"),
    ("aws:iam/rolePolicy:RolePolicy", f"{ARCH_HUB}-deploy"),
}


def test_architecture_hub_migration_transform_covers_every_pr44_resource(pulumi_mocks):
    """The README's alias transform sees exactly PR #44's resources, under their old names."""
    aliased = set()

    def adopt(args: pulumi.ResourceTransformationArgs):
        if not isinstance(args.resource, pulumi.CustomResource):
            return None  # the component wrappers did not exist in PR #44
        aliased.add((args.type_, args.name))
        alias = pulumi.ResourceOptions(
            aliases=[pulumi.Alias(parent=pulumi.ROOT_STACK_RESOURCE)]
        )
        return pulumi.ResourceTransformationResult(
            args.props, pulumi.ResourceOptions.merge(args.opts, alias)
        )

    deploy(
        pulumi_mocks,
        name=ARCH_HUB,
        opts=pulumi.ResourceOptions(transformations=[adopt]),
    )
    assert aliased == PR44_RESOURCES
    assert {(r.typ, r.name) for r in pulumi_mocks.resources} >= PR44_RESOURCES
