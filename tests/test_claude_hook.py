from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "sdk" / "python" / "src"
POLICY_PATH = ROOT / "policy" / "examples" / "claude-code.yaml"


def run_hook(
    payload: dict,
    receipts_path: Path,
    *,
    echo_first_suggestion: bool = False,
    extra_args: list[str] | None = None,
) -> tuple[str, list[dict]]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC)
    command = [
        sys.executable,
        "-m",
        "dualkey.claude_hook",
        "--policy",
        str(POLICY_PATH),
        "--receipts",
        str(receipts_path),
    ]
    command.extend(extra_args or [])
    if echo_first_suggestion:
        command.append("--echo-first-suggestion")

    process = subprocess.run(
        command,
        input=json.dumps(payload),
        text=True,
        capture_output=True,
        env=env,
        check=True,
    )
    receipts = [json.loads(line) for line in receipts_path.read_text(encoding="utf-8").splitlines()]
    return process.stdout.strip(), receipts


def test_claude_pretooluse_denies_destructive_bash(tmp_path: Path) -> None:
    stdout, receipts = run_hook(
        {
            "session_id": "sess_1",
            "cwd": "/repo",
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /tmp/demo"},
            "tool_use_id": "toolu_1",
        },
        tmp_path / "receipts.jsonl",
    )

    output = json.loads(stdout)
    assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert receipts[0]["decision"] == "deny"
    assert receipts[0]["status"] == "claude_pre_tool_use"


def test_claude_permission_request_allows_and_echoes_suggestion(tmp_path: Path) -> None:
    stdout, receipts = run_hook(
        {
            "session_id": "sess_2",
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
        tmp_path / "receipts.jsonl",
        echo_first_suggestion=True,
    )

    output = json.loads(stdout)
    assert output["hookSpecificOutput"]["hookEventName"] == "PermissionRequest"
    assert output["hookSpecificOutput"]["decision"]["updatedPermissions"][0]["destination"] == "session"
    assert receipts[0]["decision"] == "allow"
    assert receipts[0]["status"] == "claude_permission_request"


def test_claude_post_tool_use_failure_writes_error_receipt(tmp_path: Path) -> None:
    stdout, receipts = run_hook(
        {
            "session_id": "sess_3",
            "cwd": "/repo",
            "permission_mode": "default",
            "hook_event_name": "PostToolUseFailure",
            "tool_name": "Bash",
            "tool_input": {"command": "npm test"},
            "tool_use_id": "toolu_3",
            "error": "Command exited with status 1",
            "is_interrupt": False,
        },
        tmp_path / "receipts.jsonl",
    )

    assert stdout == ""
    assert receipts[0]["status"] == "error"
    assert receipts[0]["error"] == "Command exited with status 1"


def test_claude_permission_request_ask_returns_no_override(tmp_path: Path) -> None:
    stdout, receipts = run_hook(
        {
            "session_id": "sess_4",
            "cwd": "/repo",
            "permission_mode": "default",
            "hook_event_name": "PermissionRequest",
            "tool_name": "Bash",
            "tool_input": {"command": "git push origin main"},
            "tool_use_id": "toolu_4",
        },
        tmp_path / "receipts.jsonl",
    )

    assert stdout == ""
    assert receipts[0]["decision"] == "ask"
    assert receipts[0]["status"] == "claude_permission_request"


def test_claude_hook_cli_can_disable_receipt_redaction(tmp_path: Path) -> None:
    stdout, receipts = run_hook(
        {
            "session_id": "sess_5",
            "cwd": "/repo",
            "permission_mode": "default",
            "hook_event_name": "PostToolUseFailure",
            "tool_name": "Bash",
            "tool_input": {"command": "curl https://example.com"},
            "tool_use_id": "toolu_5",
            "error": "Authorization: Bearer topsecretvalue",
            "is_interrupt": False,
        },
        tmp_path / "receipts.jsonl",
        extra_args=["--receipt-redaction", "off"],
    )

    assert stdout == ""
    assert receipts[0]["error"] == "Authorization: Bearer topsecretvalue"
