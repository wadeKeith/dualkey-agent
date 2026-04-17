from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policy" / "examples" / "claude-code.yaml"


def _hook_command() -> list[str]:
    if cli := shutil.which("dualkey-claude-hook"):
        return [cli]
    return [sys.executable, "-m", "dualkey.claude_hook"]


def _run_hook(
    payload: dict[str, object],
    receipts_path: Path,
    *,
    extra_args: list[str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], list[dict[str, object]]]:
    process = subprocess.run(
        [
            *_hook_command(),
            "--policy",
            str(POLICY_PATH),
            "--receipts",
            str(receipts_path),
            *(extra_args or []),
        ],
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        check=False,
        env=os.environ.copy(),
    )
    receipts = []
    if receipts_path.exists():
        receipts = [
            json.loads(line)
            for line in receipts_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    return process, receipts


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> int:
    with TemporaryDirectory(prefix="dualkey-claude-hook-smoke-") as tmpdir:
        root = Path(tmpdir)

        deny_process, deny_receipts = _run_hook(
            {
                "session_id": "sess_smoke_1",
                "cwd": "/repo",
                "permission_mode": "default",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "rm -rf /tmp/demo"},
                "tool_use_id": "toolu_smoke_1",
            },
            root / "deny.jsonl",
        )
        _assert(deny_process.returncode == 0, f"claude hook deny smoke failed: {deny_process.stderr}")
        deny_output = json.loads(deny_process.stdout)
        _assert(
            deny_output["hookSpecificOutput"]["permissionDecision"] == "deny",
            f"expected deny decision, got {deny_process.stdout}",
        )
        _assert(deny_receipts[0]["decision"] == "deny", f"missing deny receipt: {deny_receipts!r}")

        allow_process, allow_receipts = _run_hook(
            {
                "session_id": "sess_smoke_2",
                "cwd": "/repo",
                "permission_mode": "default",
                "hook_event_name": "PermissionRequest",
                "tool_name": "WebFetch",
                "tool_input": {"url": "https://example.com"},
                "permission_suggestions": [
                    {
                        "type": "addRules",
                        "rules": [{"toolName": "WebFetch", "ruleContent": "https://example.com"}],
                        "behavior": "allow",
                        "destination": "session",
                    }
                ],
            },
            root / "allow.jsonl",
            extra_args=["--echo-first-suggestion"],
        )
        _assert(allow_process.returncode == 0, f"claude hook allow smoke failed: {allow_process.stderr}")
        allow_output = json.loads(allow_process.stdout)
        _assert(
            allow_output["hookSpecificOutput"]["decision"]["behavior"] == "allow",
            f"expected allow decision, got {allow_process.stdout}",
        )
        _assert(allow_receipts[0]["decision"] == "allow", f"missing allow receipt: {allow_receipts!r}")

    print("dualkey-claude-hook smoke checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
