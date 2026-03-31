import copy
from typing import TypedDict

import pulumi
import pulumi_aws as aws


class BucketArgs(TypedDict):
    """
    Placeholder args type required by Pulumi's Analyzer.

    Real configuration is passed via:
    - args: strongly-typed aws.s3.BucketArgs
    """

    pass


class Bucket(pulumi.ComponentResource):
    def __init__(
        self,
        name: str,
        args: aws.s3.BucketArgs | None = None,
        opts: pulumi.ResourceOptions | None = None,
    ) -> None:
        super().__init__("components:aws/s3/bucket:Bucket", name, None, opts)

        # defensive copy: don't mutate caller's args
        if args is not None:
            bucket_args = copy.deepcopy(args)
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

        # ----- Default lifecycle rules -----
        #
        # Most of our S3 buckets currently have no lifecycle rules, which is
        # expensive for versioned buckets. here we provide a sensible default:
        #
        #   - keep the *current* version of every object forever
        #   - delete *noncurrent* versions once they have been noncurrent
        #     for 90 days
        #
        # in S3 terms:
        #   - when you overwrite/delete an object in a versioned bucket, the
        #     previous copy becomes a “noncurrent” version
        #   - this rule says “for every noncurrent version in this bucket,
        #     delete it once it’s been noncurrent for 90 days”
        #
        # this default rule does NOT:
        #   - delete the latest (current) version of any object
        #   - do anything in an unversioned bucket (it only applies when
        #     versioning is enabled)
        #
        # Net effect: we keep the current state of our data indefinitely,
        # plus 90 days of history for rollbacks/audits. Anything older than
        # 90 days worth of history gets deleted.
        #
        # Overriding behaviour:
        #   - if the caller sets lifecycle_rules on the BucketArgs, we respect
        #     their configuration and do NOT apply this default.
        #   - to completely disable lifecycle for a given bucket, pass:
        #
        #       my_bucket = Bucket(
        #           "my-bucket",
        #           args=aws.s3.BucketArgs(
        #               lifecycle_rules=[],
        #           ),
        #       )
        #
        #   - to implement a different policy (e.g. "expire current objects
        #     after X days"), supply your own lifecycle_rules instead of
        #     relying on this default:
        #
        #       my_bucket = Bucket(
        #           "my-bucket",
        #           args=aws.s3.BucketArgs(
        #               lifecycle_rules=[
        #                   aws.s3.BucketLifecycleRuleArgs(
        #                       enabled=True,
        #                       id="expire-current-after-x-days",
        #                       expiration=aws.s3.BucketLifecycleRuleExpirationArgs(
        #                           days=30,  # delete current versions after 30 days
        #                       ),
        #                       noncurrent_version_expiration=aws.s3.
        #                       BucketLifecycleRuleNoncurrentVersionExpirationArgs(
        #                           days=100,  # clean up noncurrent after 100 days
        #                       ),
        #                   ),
        #               ],
        #           ),
        #       )
        #
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
