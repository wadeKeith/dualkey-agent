from __future__ import annotations

import json
from pathlib import Path

from dualkey.demo import run_named_scenario
from dualkey.receipts import ReceiptSettings


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policy" / "examples" / "dualkey.yaml"


def test_git_push_demo_blocks_secret_write_and_executes_push(tmp_path: Path) -> None:
    receipts_path = tmp_path / "receipts.jsonl"

    report = run_named_scenario(
        "git-push",
        policy_path=POLICY_PATH,
        auto_approve=True,
        receipts_path=receipts_path,
    )

    assert report[0]["status"] == "blocked"
    assert report[0]["tool"] == "filesystem.write"
    assert report[1]["status"] == "executed"
    assert report[1]["tool"] == "shell.exec"

    receipts = [json.loads(line) for line in receipts_path.read_text(encoding="utf-8").splitlines()]
    assert len(receipts) == 2
    assert all(receipt["receipt_hash"].startswith("hmac-sha256:") for receipt in receipts)


def test_dangerous_shell_demo_is_denied(tmp_path: Path) -> None:
    receipts_path = tmp_path / "receipts.jsonl"

    report = run_named_scenario(
        "dangerous-shell",
        policy_path=POLICY_PATH,
        auto_approve=True,
        receipts_path=receipts_path,
    )

    assert len(report) == 1
    assert report[0]["status"] == "blocked"
    assert "deny" in report[0]["error"]


def test_demo_receipt_settings_can_limit_stored_history(tmp_path: Path) -> None:
    receipts_path = tmp_path / "receipts.jsonl"

    report = run_named_scenario(
        "git-push",
        policy_path=POLICY_PATH,
        auto_approve=True,
        receipts_path=receipts_path,
        receipt_settings=ReceiptSettings(redact_sensitive_values=False, max_receipts=1),
    )

    assert len(report) == 2
    receipts = [json.loads(line) for line in receipts_path.read_text(encoding="utf-8").splitlines()]
    assert len(receipts) == 1
    assert receipts[0]["trace_id"] == "trace_gitpush_push"
