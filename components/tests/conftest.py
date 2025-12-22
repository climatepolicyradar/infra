import pulumi  # type: ignore
import pytest  # type: ignore


class TestMocks(pulumi.runtime.Mocks):
    """@see: https://www.pulumi.com/docs/iac/guides/testing/unit/#add-mocks"""

    def __init__(self) -> None:
        self.resources: list[pulumi.runtime.MockResourceArgs] = []

    def new_resource(
        self,
        args: pulumi.runtime.MockResourceArgs,
    ) -> tuple[str, dict[str, object]]:
        self.resources.append(args)

        resource_id = f"{args.name}_id"
        outputs = dict(args.inputs)
        return resource_id, outputs

    def call(
        self, args: pulumi.runtime.MockCallArgs
    ) -> tuple[dict[str, object], list[tuple[str, str]]]:
        return {}, []


@pytest.fixture(autouse=True)
def pulumi_mocks():
    mocks = TestMocks()
    pulumi.runtime.set_mocks(mocks, preview=False)
    return mocks
