import json
from typing import TypedDict

import pulumi
import pulumi_aws as aws


class RepositoryArgs(TypedDict):
    """Required by Pulumi's package registry.

    We just create an empty class to satisfy the requirement.
    """

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

        aws_ecr_repository_args = aws_ecr_repository_args or aws.ecr.RepositoryArgs(
            name=name,
        )

        self.aws_ecr_repository = aws.ecr.Repository(
            name,
            args=aws_ecr_repository_args,
            opts=pulumi.ResourceOptions(parent=self),
        )

        aws_ecr_lifecycle_policy_policy = aws_ecr_lifecycle_policy_policy or json.dumps(
            {
                "rules": [
                    {
                        "rulePriority": 1,
                        "description": "Keep last 50 images",
                        "selection": {
                            "tagStatus": "any",
                            "countType": "imageCountMoreThan",
                            # Keeping 50 images provides roughly 14 days of history based on our busiest
                            # push frequencies (up to ~50 images pushed in a 14 day window).
                            "countNumber": 50,
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
