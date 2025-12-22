import json

import pulumi  # type: ignore
import pulumi_aws as aws  # type: ignore
from typing import TypedDict


# These are required by Pulumis package registry, so we just create empty ones
class ECRRepositoryArgs(TypedDict):
    pass


class ECRRepository(pulumi.ComponentResource):
    def __init__(
        self,
        name: str,
        args: ECRRepositoryArgs = ECRRepositoryArgs(),
        aws_ecr_repository_args: aws.ecr.RepositoryArgs | None = None,
        aws_ecr_lifecycle_policy_policy: pulumi.Input[str] | None = None,
        component_opts: pulumi.ResourceOptions | None = None,
    ):
        super().__init__("cpr:ecr:Repository", name, None, component_opts)

        """repository"""
        aws_ecr_repository_args = aws_ecr_repository_args or aws.ecr.RepositoryArgs(
            name=name,
        )

        self.repository = aws.ecr.Repository(
            name,
            args=aws_ecr_repository_args,
            opts=pulumi.ResourceOptions(parent=self),
        )

        """lifecycle policy"""
        aws_ecr_lifecycle_policy_policy = aws_ecr_lifecycle_policy_policy or json.dumps(
            {
                "rules": [
                    {
                        "rulePriority": 1,
                        "description": "Expire images older than 14 days",
                        "selection": {
                            "tagStatus": "any",
                            "countType": "sinceImagePushed",
                            "countUnit": "days",
                            # Two weeks as this is the default retention period for logs and other resources
                            # After 2 weeks, the code and other dependant systems would have been updated
                            # And being able to rollback further might actually cause more issues
                            "countNumber": 14,
                        },
                        "action": {"type": "expire"},
                    }
                ]
            }
        )

        self.lifecycle_policy = aws.ecr.LifecyclePolicy(
            f"{name}-lifecycle",
            repository=self.repository.name,
            policy=aws_ecr_lifecycle_policy_policy,
            opts=pulumi.ResourceOptions(parent=self),
        )

        self.register_outputs({})
