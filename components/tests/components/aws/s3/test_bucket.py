import pulumi
import pulumi_aws as aws
from components.aws.s3.bucket import Bucket
from pulumi.provider.experimental.analyzer import Analyzer


@pulumi.runtime.test
def test_bucket_defaults(pulumi_mocks):
    """
    default usage of the Bucket component should:
    - create exactly one aws:s3/bucket:Bucket
    - enable versioning
    - enable AES256 SSE with bucket keys
    - apply the golden-path lifecycle rule (noncurrent versions expire after 90 days)
    """
    component = Bucket("test-default-bucket")

    def check_resources(_):
        resources = pulumi_mocks.resources

        aws_s3_buckets = [r for r in resources if r.typ == "aws:s3/bucket:Bucket"]
        assert len(aws_s3_buckets) == 1

        bucket = aws_s3_buckets[0]

        versioning = bucket.inputs.get("versioning") or bucket.inputs.get(
            "versioning", {}
        )
        assert versioning.get("enabled") is True

        sse_config = bucket.inputs.get(
            "serverSideEncryptionConfiguration"
        ) or bucket.inputs.get("server_side_encryption_configuration")
        assert sse_config is not None

        rule = sse_config["rule"]
        default_sse = rule["applyServerSideEncryptionByDefault"]
        assert default_sse["sseAlgorithm"] == "AES256"
        assert rule.get("bucketKeyEnabled") is True

        lifecycle_rules = bucket.inputs.get("lifecycleRules") or bucket.inputs.get(
            "lifecycle_rules"
        )
        assert lifecycle_rules, "expected lifecycle rules to be set by default"

        rule0 = lifecycle_rules[0]
        nve = rule0.get("noncurrentVersionExpiration") or rule0.get(
            "noncurrent_version_expiration"
        )
        expected_days = 90
        assert nve["days"] == expected_days

    return pulumi.Output.all(
        component.aws_s3_bucket.id,
    ).apply(check_resources)


@pulumi.runtime.test
def test_bucket_lifecycle_override_custom_rule(pulumi_mocks):
    """
    when the caller provides lifecycle_rules on BucketArgs, the component
    should respect those rules and NOT apply the default 90 day noncurrent
    cleanup rule, while keeping versioning + SSE enabled.
    """
    expected_days = 21

    component = Bucket(
        "test-rds-backups",
        args={
            "aws_s3_bucket_args": aws.s3.BucketArgs(
                bucket="cpr-production-rds",
                tags={"service": "rds-backups"},
                lifecycle_rules=[
                    aws.s3.BucketLifecycleRuleArgs(
                        enabled=True,
                        id="SQL-Dump-Retention-3weeks",
                        prefix="dumps/",
                        expiration=aws.s3.BucketLifecycleRuleExpirationArgs(
                            days=expected_days,
                        ),
                    )
                ],
            )
        },
    )

    def check_resources(_):
        resources = pulumi_mocks.resources

        aws_s3_buckets = [r for r in resources if r.typ == "aws:s3/bucket:Bucket"]
        assert len(aws_s3_buckets) == 1

        bucket = aws_s3_buckets[0]

        lifecycle_rules = bucket.inputs.get("lifecycleRules") or bucket.inputs.get(
            "lifecycle_rules"
        )
        assert lifecycle_rules is not None
        assert len(lifecycle_rules) == 1

        rule = lifecycle_rules[0]
        assert rule["id"] == "SQL-Dump-Retention-3weeks"
        assert rule["prefix"] == "dumps/"

        expiration = rule.get("expiration") or rule.get("Expiration")
        assert expiration["days"] == expected_days

        nve = rule.get("noncurrentVersionExpiration") or rule.get(
            "noncurrent_version_expiration"
        )
        assert nve is None

        versioning = bucket.inputs.get("versioning") or bucket.inputs.get(
            "versioning", {}
        )
        assert versioning.get("enabled") is True

        sse_config = bucket.inputs.get(
            "serverSideEncryptionConfiguration"
        ) or bucket.inputs.get("server_side_encryption_configuration")
        assert sse_config is not None

        rule_sse = sse_config["rule"]
        default_sse = rule_sse["applyServerSideEncryptionByDefault"]
        assert default_sse["sseAlgorithm"] == "AES256"
        assert rule_sse.get("bucketKeyEnabled") is True

    return pulumi.Output.all(
        component.aws_s3_bucket.id,
    ).apply(check_resources)


@pulumi.runtime.test
def test_bucket_lifecycle_override_disable_rules(pulumi_mocks):
    """
    when the caller explicitly disables lifecycle rules (enabled=False),
    the component should not add its own default rule and should preserve
    the disabled rule as-is.
    """
    component = Bucket(
        "test-disable-lifecycle",
        args={
            "aws_s3_bucket_args": aws.s3.BucketArgs(
                bucket="no-lifecycle-bucket",
                lifecycle_rules=[
                    aws.s3.BucketLifecycleRuleArgs(
                        enabled=False,
                        id="no-lifecycle",
                    )
                ],
            )
        },
    )

    def check_resources(_):
        resources = pulumi_mocks.resources

        aws_s3_buckets = [r for r in resources if r.typ == "aws:s3/bucket:Bucket"]
        assert len(aws_s3_buckets) == 1

        bucket = aws_s3_buckets[0]

        lifecycle_rules = bucket.inputs.get("lifecycleRules") or bucket.inputs.get(
            "lifecycle_rules"
        )
        assert lifecycle_rules is not None
        assert len(lifecycle_rules) == 1

        rule = lifecycle_rules[0]
        assert rule["id"] == "no-lifecycle"
        assert rule["enabled"] is False or rule["enabled"] == "False"

        assert (
            rule.get("noncurrentVersionExpiration")
            or rule.get("noncurrent_version_expiration")
        ) is None
        assert rule.get("expiration") is None

    return pulumi.Output.all(
        component.aws_s3_bucket.id,
    ).apply(check_resources)


def test_analyze_s3_bucket_component():
    """
    sanity-check that the Bucket component is valid from the Pulumi
    package/analyzer point of view, mirroring the ECR Repository test.
    """
    analyzer = Analyzer(name="test")
    try:
        analyzer.analyze_component(Bucket)
        print(f"✓ {Bucket.__name__} is valid")
    except Exception as e:
        print(f"✗ {Bucket.__name__}: {e}")
        raise
