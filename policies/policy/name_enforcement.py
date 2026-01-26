"""Policies to enforce naming conventions on AWS resources."""

import re

from pulumi_policy import (
    EnforcementLevel,
    PolicyPack,
    ReportViolation,
    ResourceValidationArgs,
    ResourceValidationPolicy,
)

# AWS naming patterns
# AWS resource names typically allow lowercase letters, numbers, hyphens
AWS_NAME_PATTERN = r"^[a-z0-9-]+$"

# ECR repository names: lowercase, numbers, hyphens, underscores, forward slashes
ECR_NAME_PATTERN = r"^[a-z0-9-_/]+$"

# S3 bucket names: lowercase, numbers, hyphens, periods
S3_BUCKET_PATTERN = r"^[a-z0-9.-]+$"


def create_name_policy(
    resource_type: str,
    name_property: str = "name",
    pattern: str | None = None,
    min_length: int | None = None,
    max_length: int | None = None,
    required: bool = True,
) -> ResourceValidationPolicy:
    """
    Create a policy that enforces naming conventions.

    :param resource_type: The Pulumi resource type to apply the policy to
    :type resource_type: str
    :param name_property: The property name that contains the resource name
    :type name_property: str
    :param pattern: Optional regex pattern the name must match
    :type pattern: str | None
    :param min_length: Minimum length of the name
    :type min_length: int | None
    :param max_length: Maximum length of the name
    :type max_length: int | None
    :param required: Whether the name property is required
    :type required: bool
    :return: A validation policy function
    :rtype: ResourceValidationPolicy
    """

    def validate_name(
        args: ResourceValidationArgs, report_violation: ReportViolation
    ) -> None:
        """
        Validate that a resource has a proper name property.

        :param args: Resource validation arguments
        :type args: ResourceValidationArgs
        :param report_violation: Function to report policy violations
        :type report_violation: ReportViolation
        """
        # Only validate resources of the specified type
        if args.resource_type != resource_type:
            return

        props = args.props
        name_value = props.get(name_property)

        if required and (name_value is None or name_value == ""):
            report_violation(
                f"Resource {resource_type} must have a '{name_property}' property",
            )
            return

        if name_value is None:
            return

        name_str = str(name_value)

        if min_length is not None and len(name_str) < min_length:
            report_violation(
                f"Resource {resource_type} '{name_property}' must be at least "
                f"{min_length} characters long",
            )

        if max_length is not None and len(name_str) > max_length:
            report_violation(
                f"Resource {resource_type} '{name_property}' must be no more "
                f"than {max_length} characters long",
            )

        if pattern is not None:
            if not re.match(pattern, name_str):
                report_violation(
                    f"Resource {resource_type} '{name_property}' must match "
                    f"pattern: {pattern}",
                )

    return validate_name


def register_policies(policy_pack: PolicyPack) -> None:
    """
    Register all naming enforcement policies.

    :param policy_pack: The policy pack to register policies with
    :type policy_pack: PolicyPack
    """
    # ECR Repository naming
    policy_pack.add_resource_validation_policy(
        ResourceValidationPolicy(
            name="ecr-repository-name-required",
            description="ECR repositories must have a name property",
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=create_name_policy(
                resource_type="aws:ecr/repository:Repository",
                name_property="name",
                pattern=ECR_NAME_PATTERN,
                min_length=2,
                max_length=256,
                required=True,
            ),
        )
    )

    # S3 Bucket naming
    policy_pack.add_resource_validation_policy(
        ResourceValidationPolicy(
            name="s3-bucket-name-required",
            description="S3 buckets must have a name property",
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=create_name_policy(
                resource_type="aws:s3/bucket:Bucket",
                name_property="bucket",
                pattern=S3_BUCKET_PATTERN,
                min_length=3,
                max_length=63,
                required=True,
            ),
        )
    )

    # Lambda Function naming
    policy_pack.add_resource_validation_policy(
        ResourceValidationPolicy(
            name="lambda-function-name-required",
            description="Lambda functions must have a name property",
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=create_name_policy(
                resource_type="aws:lambda/function:Function",
                name_property="name",
                pattern=AWS_NAME_PATTERN,
                min_length=1,
                max_length=64,
                required=True,
            ),
        )
    )

    # IAM Role naming
    policy_pack.add_resource_validation_policy(
        ResourceValidationPolicy(
            name="iam-role-name-required",
            description="IAM roles must have a name property",
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=create_name_policy(
                resource_type="aws:iam/role:Role",
                name_property="name",
                pattern=AWS_NAME_PATTERN,
                min_length=1,
                max_length=64,
                required=True,
            ),
        )
    )

    # Component resources - check for name in args
    def validate_component_name(
        args: ResourceValidationArgs,
        report_violation: ReportViolation,
    ) -> None:
        """
        Validate that component resources have a name.

        :param args: Resource validation arguments
        :type args: ResourceValidationArgs
        :param report_violation: Function to report policy violations
        :type report_violation: ReportViolation
        """
        # Only validate component resources
        if not args.resource_type.startswith("components:"):
            return

        if not args.name or args.name == "":
            report_violation(
                f"Component resource {args.resource_type} must have a name property",
            )

    policy_pack.add_resource_validation_policy(
        ResourceValidationPolicy(
            name="component-resources-name-required",
            description="Component resources must have a name",
            enforcement_level=EnforcementLevel.MANDATORY,
            validate=validate_component_name,
        )
    )
