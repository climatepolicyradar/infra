from pulumi.provider.experimental import component_provider_host
from src.components.ecr_repository import ECRRepository

if __name__ == "__main__":
    component_provider_host(name="ecr-repository-component", components=[ECRRepository])
