import copy
from typing import TypedDict

import pulumi
import pulumi_aws as aws


class BucketArgs(TypedDict):
    """
    Placeholder args type required by Pulumi's Analyzer.

    Real configuration is passed via:
    - aws_s3_bucket_args: strongly-typed BucketArgs
    """

    pass


class Bucket(pulumi.ComponentResource):
    def __init__(
        self,
        name: str,
        args: BucketArgs = BucketArgs(),
        aws_s3_bucket_args: aws.s3.BucketArgs | None = None,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        super().__init__("components:aws/s3/bucket:Bucket", name, None, opts)

        # defensive copy: don't mutate caller's args
        if aws_s3_bucket_args is not None:
            bucket_args = copy.deepcopy(aws_s3_bucket_args)
        else:
            bucket_args = aws.s3.BucketArgs()

        # ----- opinionated defaults (only if unset) -----

        if getattr(bucket_args, "bucket", None) is None:
            bucket_args.bucket = name

        if getattr(bucket_args, "versioning", None) is None:
            bucket_args.versioning = aws.s3.BucketVersioningArgs(enabled=True)

        if getattr(bucket_args, "server_side_encryption_configuration", None) is None:
            bucket_args.server_side_encryption_configuration = (
                aws.s3.BucketServerSideEncryptionConfigurationArgs(
                    rule=aws.s3.BucketServerSideEncryptionConfigurationRuleArgs(
                        apply_server_side_encryption_by_default=aws.s3.
                        BucketServerSideEncryptionConfigurationRuleApplyServerSideEncryptionByDefaultArgs(
                            sse_algorithm="AES256",
                        ),
                        bucket_key_enabled=True,
                    )
                )
            )

        # ----- lifecycle rules -----
        #
        # if caller sets lifecycle_rules in aws_s3_bucket_args, we respect it.
        # if not, we apply the golden-path default.
        if getattr(bucket_args, "lifecycle_rules", None) is None:
            bucket_args.lifecycle_rules = [
                aws.s3.BucketLifecycleRuleArgs(
                    enabled=True,
                    id="noncurrent-version-cleanup-90d",
                    noncurrent_version_expiration=aws.s3.
                    BucketLifecycleRuleNoncurrentVersionExpirationArgs(
                        days=90,
                    ),
                )
            ]

        # ----- underlying aws bucket -----
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
