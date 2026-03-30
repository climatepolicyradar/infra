from typing import Optional

import pulumi
import pulumi_aws as aws


class Bucket(pulumi.ComponentResource):
    """
    s3 bucket "golden path" component.

    wraps aws.s3.Bucket, applying best-practice defaults for:
    - encryption
    - versioning
    - lifecycle rules

    callers:
    - pass aws_s3_bucket_args when they want control
    - optionally pass override_lifecycle_rules for a simple dict-based override
    """

    def __init__(
        self,
        name: str,
        aws_s3_bucket_args: Optional[aws.s3.BucketArgs] = None,
        override_lifecycle_rules: Optional[list[dict]] = None,
        opts: Optional[pulumi.ResourceOptions] = None,
    ) -> None:
        super().__init__("components:aws/s3/bucket:Bucket", name, None, opts)

        # If caller didn't supply any base args, start from an empty args object
        bucket_args = aws_s3_bucket_args or aws.s3.BucketArgs()

        # ----- Apply opinionated defaults only if caller hasn't set them -----

        # Default bucket name to pulumi logical name if not given
        if bucket_args.bucket is None:
            bucket_args.bucket = name

        if bucket_args.versioning is None:
            bucket_args.versioning = aws.s3.BucketVersioningArgs(enabled=True)

        # Enable SSE s3-managed keys, bucket key enabled
        if bucket_args.server_side_encryption_configuration is None:
            bucket_args.server_side_encryption_configuration = aws.s3.BucketServerSideEncryptionConfigurationArgs(
                rule=aws.s3.BucketServerSideEncryptionConfigurationRuleArgs(
                    apply_server_side_encryption_by_default=aws.s3.BucketServerSideEncryptionConfigurationRuleApplyServerSideEncryptionByDefaultArgs(
                        sse_algorithm="AES256",
                    ),
                    bucket_key_enabled=True,
                )
            )

        # Either caller-supplied lifecycle dicts or a sensible default
        if override_lifecycle_rules is not None:
            bucket_args.lifecycle_rules = [
                aws.s3.BucketLifecycleRuleArgs(
                    enabled=lr.get("enabled", True),
                    id=lr.get("id"),
                    prefix=lr.get("prefix"),
                    expiration=(
                        aws.s3.BucketLifecycleRuleExpirationArgs(
                            days=lr["expiration"]["days"],
                        )
                        if lr.get("expiration")
                        else None
                    ),
                    noncurrent_version_expiration=(
                        aws.s3.BucketLifecycleRuleNoncurrentVersionExpirationArgs(
                            days=lr["noncurrent_version_expiration"]["days"],
                        )
                        if lr.get("noncurrent_version_expiration")
                        else None
                    ),
                )
                for lr in override_lifecycle_rules
            ]

        else:
            # Golden path default: keep current versions, expire noncurrent after 90 days
            bucket_args.lifecycle_rules = [
                aws.s3.BucketLifecycleRuleArgs(
                    enabled=True,
                    id="noncurrent-version-cleanup-90d",
                    noncurrent_version_expiration=aws.s3.BucketLifecycleRuleNoncurrentVersionExpirationArgs(
                        days=90,
                    ),
                )
            ]

        # ----- Underlying aws bucket -----
        self.aws_s3_bucket = aws.s3.Bucket(
            name,
            args=bucket_args,
            opts=pulumi.ResourceOptions(parent=self),
        )

        self.register_outputs(
            {
                "bucket_name": self.aws_s3_bucket.bucket,
                "bucket_arn": self.aws_s3_bucket.arn,
            }
        )
