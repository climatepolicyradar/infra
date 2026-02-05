import json
from typing import TypedDict

import pulumi
import pulumi_aws as aws


# These are required by Pulumis package registry, so we just create empty ones
class RepositoryArgs(TypedDict):
    pass


class Repository(pulumi.ComponentResource):
    def __init__(
        self,
        name: str,
        args: RepositoryArgs = RepositoryArgs(),
        opts: pulumi.ResourceOptions | None = None,
        aws_ecr_repository_args: aws.ecr.RepositoryArgs | None = None,
        # this is not typed as Pulumi has not typed it in their system
        aws_ecr_lifecycle_policy_policy: pulumi.Input[str] | None = None,
    ):
        super().__init__("components:aws/ecr/repository:Repository", name, None, opts)

        """repository"""
        aws_ecr_repository_args = aws_ecr_repository_args or aws.ecr.RepositoryArgs(
            name=name,
        )

        self.aws_ecr_repository = aws.ecr.Repository(
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
                            # Two weeks is a general default retention period for logs and other resources.
                            # After 2 weeks other dependant systems have often been updated to the point
                            # beyond being able to rollback.
                            "countNumber": 14,
                        },
                        "action": {"type": "expire"},
                    }
                ]
            }
        )

        self.aws_ecr_lifecycle_policy = aws.ecr.LifecyclePolicy(
            f"{name}-lifecycle",
            repository=self.aws_ecr_repository.name,
            policy=aws_ecr_lifecycle_policy_policy,
            opts=pulumi.ResourceOptions(parent=self),
        )

        self.register_outputs({})
