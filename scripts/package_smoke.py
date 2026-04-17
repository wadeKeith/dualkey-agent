from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


def _run(*args: str) -> None:
    process = subprocess.run(
        [sys.executable, *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if process.returncode != 0:
        raise SystemExit(
            f"command failed: {sys.executable} {' '.join(args)}\n"
            f"stdout:\n{process.stdout}\n"
            f"stderr:\n{process.stderr}"
        )


def main() -> int:
    shutil.rmtree(ROOT / "dist", ignore_errors=True)
    shutil.rmtree(ROOT / "build", ignore_errors=True)

    _run("-m", "build", "--sdist", "--wheel")
    artifacts = sorted((ROOT / "dist").glob("*"))
    if not artifacts:
        raise SystemExit("package smoke failed: dist/ is empty after build")

    _run("-m", "twine", "check", *[str(path) for path in artifacts])
    print("package smoke checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
