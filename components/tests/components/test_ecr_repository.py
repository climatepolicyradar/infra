import json

import pulumi  # type: ignore
from src.components.ecr_repository import ECRRepository
from pulumi.provider.experimental.analyzer import Analyzer


@pulumi.runtime.test
def test_ecr_repository(pulumi_mocks):
    component = ECRRepository("test")

    def check_resources(_):
        resources = pulumi_mocks.resources
        aws_ecr_repository = [
            r for r in resources if r.typ == "aws:ecr/repository:Repository"
        ]
        assert len(aws_ecr_repository) == 1

        # if not specified we should have a default `LifecyclePolicy`
        aws_ecr_lifecycle_policy = [
            r for r in resources if r.typ == "aws:ecr/lifecyclePolicy:LifecyclePolicy"
        ]
        assert len(aws_ecr_lifecycle_policy) == 1

        # Check the retention policy is 14 days
        policy = json.loads(aws_ecr_lifecycle_policy[0].inputs["policy"])
        assert len(policy["rules"]) == 1
        assert policy["rules"][0]["selection"]["countNumber"] == 14
        assert policy["rules"][0]["selection"]["countUnit"] == "days"

    # @see: https://www.pulumi.com/docs/iac/guides/testing/unit/#write-the-tests
    return pulumi.Output.all(
        component.repository.id, component.lifecycle_policy.id
    ).apply(check_resources)


def test_analyze_ecr_repository():
    analyzer = Analyzer(name="test")
    try:
        analyzer.analyze_component(ECRRepository)
        print(f"✓ {ECRRepository.__name__} is valid")
    except Exception as e:
        print(f"✗ {ECRRepository.__name__}: {e}")
        raise
