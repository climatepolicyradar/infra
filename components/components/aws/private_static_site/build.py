"""Bundle the sign-in Lambda: auth/handler.py plus auth/requirements.txt, as Linux arm64 wheels for RUNTIME.

Runs at `pulumi up`/`preview` time on the deployer's machine (needs `uv` on PATH and PyPI access), as
architecture-hub's build_auth.py did. The bundle is cached per user, keyed by the handler, requirements
and runtime, so an unchanged handler gives an unchanged archive and no Lambda update.
"""

import functools
import hashlib
import os
import shutil
import subprocess  # nosec B404: runs uv with fixed arguments
import tempfile
from pathlib import Path

HERE = Path(__file__).parent
AUTH = HERE / "auth"
RUNTIME = "python3.13"


def _cache_root() -> Path:
    # Per user, never a shared temp dir: whatever is here is shipped to the Lambda.
    base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    root = Path(base) / "cpr-components" / "private-static-site"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    return root


def bundle_key() -> str:
    h = hashlib.sha256(RUNTIME.encode())
    for name in ("handler.py", "requirements.txt"):
        h.update((AUTH / name).read_bytes())
    return h.hexdigest()[:16]


@functools.cache
def build() -> Path:
    """The directory holding the Lambda bundle, built if not already cached."""
    root = _cache_root()
    out = root / f"auth-{bundle_key()}"
    if (out / "handler.py").exists():
        return out
    tmp = Path(tempfile.mkdtemp(dir=root, prefix=".building-"))
    try:
        subprocess.run(  # nosec B603 B607
            [
                "uv", "pip", "install", "--quiet",
                "--target", str(tmp),
                "--requirements", str(AUTH / "requirements.txt"),
                "--python-platform", "aarch64-manylinux_2_28",
                "--python-version", RUNTIME.removeprefix("python"),
                "--only-binary", ":all:",
            ],
            check=True,
        )  # fmt: skip
        shutil.copy(AUTH / "handler.py", tmp / "handler.py")
        try:
            tmp.rename(out)  # atomic: a half-built bundle is never picked up
        except OSError:
            if not (out / "handler.py").exists():  # else another run finished it first
                raise
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return out


if __name__ == "__main__":
    print(build())
