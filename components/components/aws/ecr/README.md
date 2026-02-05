# ECR

## Repository

### import

If you are importing from a pulumi_aws.ecr.Repository

e.g.

```python

# Replace this with the below components
aws_ecr_repository = aws.ecr.Repository(
    "my-aws-ecr-repository",
    name="my-repo",
    opts=pulumi.ResourceOptions(protect=True),
)

# Note - names must match
components_aws_ecr_repository = components_aws.ecr.Repository(
    name="my-aws-ecr-repository",
)
```

```bash

# If the resource was protected
pulumi state unprotect 'urn:pulumi:<stack>::<project>::aws:ecr/repository:Repository::my-aws-ecr-repository'

# Delete the pulumi state for that resource, retaining the AWS resource
pulumi state delete 'urn:pulumi:<stack>::<project>::aws:ecr/repository:Repository::my-aws-ecr-repository'

# This should create the new pulumi state for this resource
# ⚠️ This will probably fail with a `RepositoryAlreadyExistsException`
pulumi up

# Now you can import the existing AWS repository into the pulumi state
# This follows the syntax `pulumi import --parent '<parent-urn>' '<type>' '<name>' '<aws-id>' --yes`
pulumi import \
  --parent 'urn:pulumi:<stack>::<project>::components:aws/ecr/repository:Repository::my-aws-ecr-repository' \
  'aws:ecr/repository:Repository' \
  'my-aws-ecr-repository' \
  'my-aws-ecr-repository'


# Get it all up and stored in the state
pulumi up
```
