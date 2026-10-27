"""Main entry point for the Pulumi Policy Pack."""

from policy.name_enforcement import register_policies
from pulumi_policy import PolicyPack

# Create the policy pack
naming_conventions_pack = PolicyPack(
    name="naming-conventions-policy",
    enforcement_level="mandatory",
    description="Policy pack to enforce naming conventions for infra resources",
)

# Register all policies
register_policies(naming_conventions_pack)
