from enum import Enum

from pulumi_aws import ecr


class ResourceType(Enum):
    ECR_REPOSITORY = ecr.Repository._type
    ECR_LIFECYCLE_POLICY = ecr.LifecyclePolicy._type
    ECR_REPOSITORY_POLICY = ecr.RepositoryPolicy._type
