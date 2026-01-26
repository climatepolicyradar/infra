# Infrastructure Policy Pack

Policy as code to enforce naming conventions and other standards across
infrastructure resources.

## Setup

Install dependencies:

```bash
cd policy
uv sync
```

## Usage

### Running policies locally

Test policies against a Pulumi program:

```bash
pulumi policy preview --policy-pack . --policy-pack-config PulumiPolicy.yaml
```

### Publishing to Pulumi Cloud

Publish the policy pack to your Pulumi organisation:

```bash
pulumi policy publish
```

### Enforcing policies

Once published, policies can be enforced at the organisation level or applied to
specific stacks via Pulumi Cloud.

## Policies

### Name Enforcement

- **ECR Repository naming**: Enforces that ECR repositories have a `name`
  property matching AWS naming conventions
- **S3 Bucket naming**: Enforces that S3 buckets have a `bucket` property
  matching AWS naming conventions
- **Lambda Function naming**: Enforces that Lambda functions have a `name`
  property
- **IAM Role naming**: Enforces that IAM roles have a `name` property
- **Component resources**: Enforces that component resources have a name

## Adding New Policies

Add new naming policies in `policies/name_enforcement.py` or create new policy
files in the `policies/` directory and register them in `main.py`.
