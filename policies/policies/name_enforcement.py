"""Policies to enforce naming conventions on AWS resources."""

import re
from typing import TypedDict

from pulumi_aws import ecr, s3
from pulumi_policy import (
    EnforcementLevel,
    PolicyPack,
    ReportViolation,
    ResourceValidationArgs,
    ResourceValidationPolicy,
)

# AWS naming patterns: resource type -> regex + constraints
#
# AWS resource names typically allow lowercase letters, numbers, hyphens
DEFAULT_AWS_NAME_PATTERN = r"^[a-z0-9-]+$"

# ECR: allows lowercase, hyphens
ECR_NAME_PATTERN = r"^[a-z-]+$"

# S3: lowercase, numbers, hyphens, periods
S3_BUCKET_PATTERN = r"^[a-z0-9.-]+$"


class _NameFieldConfig(TypedDict):
    """Config for a single name-like property on a resource."""

    name_property: str
    pattern: str
    min_characters: int
    max_characters: int


# Each resource type declares one or more name properties to validate.
# All are mandatory and must satisfy pattern and length rules.
RESOURCE_NAME_CONFIG: dict[str, list[_NameFieldConfig]] = {
    ecr.Repository._type: [
        {
            "name_property": "name",
            "pattern": ECR_NAME_PATTERN,
            "min_characters": 2,
            "max_characters": 256,
        },
    ],
    # TODO: switch to s3.BucketV2 when we've migrated to the new version
    s3.Bucket._type: [
        {
            "name_property": "bucket",
            "pattern": S3_BUCKET_PATTERN,
            "min_characters": 3,
            "max_characters": 63,
        },
        {
            "name_property": "resource_name",
            "pattern": DEFAULT_AWS_NAME_PATTERN,
            "min_characters": 1,
            "max_characters": 256,
        },
    ],
}


def _resource_slug(resource_type: str) -> str:
    """Derive a short slug from a Pulumi resource type for policy names.

    :param resource_type: e.g. "aws:ecr/repository:Repository"
    :type resource_type: str
    :return: e.g. "ecr-repository"
    :rtype: str
    """
    parts = resource_type.split(":")
    segment = parts[1] if len(parts) >= 2 else "resource"
    return segment.replace("/", "-").lower()


def _validate_names_required(
    props: dict,
    fields: list[_NameFieldConfig],
    resource_type: str,
    report_violation: ReportViolation,
) -> None:
    """Check that each name property is present and non-empty.

    :param props: Resource input props
    :type props: dict
    :param fields: Name field configs (only name_property is used)
    :type fields: list[_NameFieldConfig]
    :param resource_type: Pulumi resource type (for messages)
    :type resource_type: str
    :param report_violation: Callback to report a violation
    :type report_violation: ReportViolation
    """
    for field in fields:
        name_property = field["name_property"]
        val = props.get(name_property)
        if val is None or val == "":
            report_violation(
                f"Resource {resource_type} must have a '{name_property}' " "property",
            )


def _validate_naming_convention(
    props: dict,
    fields: list[_NameFieldConfig],
    resource_type: str,
    report_violation: ReportViolation,
) -> None:
    """Check pattern and length for each name property when present.

    Skips fields that are missing or empty; names-required policy covers those.

    :param props: Resource input props
    :type props: dict
    :param fields: Name field configs (pattern, min/max used)
    :type fields: list[_NameFieldConfig]
    :param resource_type: Pulumi resource type (for messages)
    :type resource_type: str
    :param report_violation: Callback to report a violation
    :type report_violation: ReportViolation
    """
    for field in fields:
        name_property = field["name_property"]
        name_value = props.get(name_property)
        if name_value is None or name_value == "":
            continue
        name_str = str(name_value)
        min_c = field["min_characters"]
        max_c = field["max_characters"]
        if len(name_str) < min_c:
            report_violation(
                f"Resource {resource_type} '{name_property}' must be at "
                f"least {min_c} characters long",
            )
        if len(name_str) > max_c:
            report_violation(
                f"Resource {resource_type} '{name_property}' must be no "
                f"more than {max_c} characters long",
            )
        if not re.match(field["pattern"], name_str):
            report_violation(
                f"Resource {resource_type} '{name_property}' must match "
                f"pattern: {field['pattern']}",
            )


def create_names_required_policy(
    resource_type: str,
    fields: list[_NameFieldConfig],
) -> ResourceValidationPolicy:
    """Policy: each listed name property must be present and non-empty.

    :param resource_type: Pulumi resource type to validate
    :param fields: Name properties that are required
    :return: A validation policy function
    :rtype: ResourceValidationPolicy
    """
    if len(fields) < 1:
        raise ValueError("At least one name field is required")

    def validate(
        args: ResourceValidationArgs, report_violation: ReportViolation
    ) -> None:
        if args.resource_type != resource_type:
            return
        _validate_names_required(args.props, fields, resource_type, report_violation)

    return validate


def create_naming_convention_policy(
    resource_type: str,
    fields: list[_NameFieldConfig],
) -> ResourceValidationPolicy:
    """Policy: when present, name properties must match pattern and length.

    :param resource_type: Pulumi resource type to validate
    :param fields: Name properties and their pattern/min/max rules
    :return: A validation policy function
    :rtype: ResourceValidationPolicy
    """
    if len(fields) < 1:
        raise ValueError("At least one name field is required")

    def validate(
        args: ResourceValidationArgs, report_violation: ReportViolation
    ) -> None:
        if args.resource_type != resource_type:
            return
        _validate_naming_convention(args.props, fields, resource_type, report_violation)

    return validate


def register_policies(policy_pack: PolicyPack) -> None:
    """
    Register all naming enforcement policies.

    Each resource type gets two policies: names required (mandatory presence)
    and naming convention (pattern + length when present).

    :param policy_pack: The policy pack to register policies with
    :type policy_pack: PolicyPack
    """
    for resource_type, fields in RESOURCE_NAME_CONFIG.items():
        if len(fields) < 1:
            raise ValueError(f"Resource type {resource_type} has no name field config")
        slug = _resource_slug(resource_type)
        required_props = [f["name_property"] for f in fields]

        policy_pack.add_resource_validation_policy(
            ResourceValidationPolicy(
                name=f"{slug}-names-required",
                description=(
                    f"{resource_type} must have mandatory name properties: "
                    f"{', '.join(required_props)}"
                ),
                enforcement_level=EnforcementLevel.MANDATORY,
                validate=create_names_required_policy(resource_type, fields),
            )
        )
        policy_pack.add_resource_validation_policy(
            ResourceValidationPolicy(
                name=f"{slug}-naming-convention",
                description=(
                    f"{resource_type} name properties must match pattern and "
                    "length rules"
                ),
                enforcement_level=EnforcementLevel.MANDATORY,
                validate=create_naming_convention_policy(resource_type, fields),
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
