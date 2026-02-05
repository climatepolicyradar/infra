import json

import pulumi
from components.component.aws.ecr import Repository
from components.component.aws.ecr.types import ResourceType
from pulumi.provider.experimental.analyzer import Analyzer


@pulumi.runtime.test
def test_repository(pulumi_mocks):
    component = Repository("test")

    def check_resources(_):
        resources = pulumi_mocks.resources
        aws_ecr_repository = [
            r for r in resources if r.typ == ResourceType.ECR_REPOSITORY.value
        ]
        assert len(aws_ecr_repository) == 1

        # if not specified we should have a default `LifecyclePolicy`
        aws_ecr_lifecycle_policy = [
            r for r in resources if r.typ == ResourceType.ECR_LIFECYCLE_POLICY.value
        ]
        assert len(aws_ecr_lifecycle_policy) == 1

        # Check the retention policy is 14 days
        policy = json.loads(aws_ecr_lifecycle_policy[0].inputs["policy"])
        assert len(policy["rules"]) == 1
        expected_number_of_days = 14
        assert policy["rules"][0]["selection"]["countNumber"] == expected_number_of_days
        assert policy["rules"][0]["selection"]["countUnit"] == "days"

    # @see: https://www.pulumi.com/docs/iac/guides/testing/unit/#write-the-tests
    return pulumi.Output.all(
        component.aws_ecr_repository.id, component.aws_ecr_lifecycle_policy.id
    ).apply(check_resources)


def test_analyze_ecr_repository():
    analyzer = Analyzer(name="test")
    try:
        analyzer.analyze_component(Repository)
        print(f"✓ {Repository.__name__} is valid")
    except Exception as e:
        print(f"✗ {Repository.__name__}: {e}")
        raise
