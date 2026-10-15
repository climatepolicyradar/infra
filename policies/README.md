# Infrastructure Policy Pack

Policy as code to enforce naming conventions and other standards across
infrastructure resources.

## Setup

Install dependencies:

```bash
cd policies
uv sync
```

## Usage

### Running policies locally

Policy packs run as part of `pulumi preview`, not as a separate command.

1. Install the policy pack’s deps (from the repo that contains `policies/`):
   `cd policies && uv sync`
2. From a Pulumi project directory (e.g. `backend/` or `bootstrap/`), run:
   `pulumi preview --policy-pack <path-to-policies-dir>`

Use the path to the directory that contains `PulumiPolicy.yaml` and
`__main__.py` (e.g. `../policies` or an absolute path). The analyzer runs that
directory as the program and uses the Python/uv runtime defined in
`PulumiPolicy.yaml`.

Optional config for the pack (JSON; see Pulumi docs for format):
`--policy-pack-config <path-to-config.json>`

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
- **Component resources**: Enforces that component resources have a name

## Adding New Policies

Add new naming policies in `policies/policy/name_enforcement.py` or create new
policy files in the `policy/` directory and register them in `main.py`.
