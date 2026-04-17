from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

from dualkey.models import ActionEnvelope, AuthorizationResult, PolicyOutcome, Receipt
from dualkey.receipts import ReceiptQuery, ReceiptStore, build_receipt


def _sample_receipt(
    *,
    suffix: str,
    trace_id: str,
    status: str,
    decision: str,
    created_at: str,
    receipt_hash: str,
    tool: str = "bash",
    intent: str = "execute",
    risk: list[str] | None = None,
    metadata: dict[str, object] | None = None,
) -> Receipt:
    action = ActionEnvelope(
        actor="dualkey-test",
        surface="shell",
        tool=tool,
        intent=intent,
        target=f"/tmp/{suffix}",
        args={"command": f"echo {suffix}"},
        risk=risk or ["test"],
        session_id="sess:test",
        trace_id=trace_id,
        metadata=metadata or {"suffix": suffix},
    )
    authorization = AuthorizationResult(
        allowed=True,
        final_decision=decision,
        policy_outcome=PolicyOutcome(
            decision="allow" if decision == "allow" else "ask",
            rule_id="test_rule",
            reason="unit test fixture",
        ),
    )
    return Receipt(
        **{
            **build_receipt(
                action=action,
                authorization=authorization,
                status=status,
                result=f"ran {suffix}",
            ).to_payload(),
            "decision": decision,
            "created_at": created_at,
            "receipt_hash": receipt_hash,
        }
    )


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "sdk" / "python" / "src"


def test_replay_cli_can_replay_bundle_directory(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path / "bundle.sqlite")
    store.append(
        _sample_receipt(
            suffix="replay-1",
            trace_id="trace:replay",
            status="waiting",
            decision="ask",
            created_at="2026-04-16T14:00:00Z",
            receipt_hash="hmac-sha256:replay-1",
        )
    )
    store.append(
        _sample_receipt(
            suffix="replay-2",
            trace_id="trace:replay",
            status="executed",
            decision="ask->approved",
            created_at="2026-04-16T14:01:00Z",
            receipt_hash="hmac-sha256:replay-2",
        )
    )
    bundle_dir = store.export_bundle(tmp_path / "audit-bundle", ReceiptQuery(trace_id="trace:replay"))

    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "dualkey.replay",
            str(bundle_dir),
            "--trace-id",
            "trace:replay",
        ],
        text=True,
        capture_output=True,
        check=True,
        env={**os.environ, "PYTHONPATH": str(SRC)},
    )

    assert "Replay source: bundle" in process.stdout
    assert "trace_id: trace:replay" in process.stdout
    assert "1. +0.0s 2026-04-16T14:00:00Z waiting ask" in process.stdout
    assert "2. +60.0s 2026-04-16T14:01:00Z executed ask->approved" in process.stdout
    assert "context: actor=dualkey-test surface=shell tool=bash intent=execute target=/tmp/replay-1 risk=test" in process.stdout


def test_replay_cli_can_export_json_from_manifest_path(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path / "replay.jsonl")
    store.append(
        _sample_receipt(
            suffix="replay-json",
            trace_id="trace:replay-json",
            status="blocked",
            decision="deny",
            created_at="2026-04-16T15:00:00Z",
            receipt_hash="hmac-sha256:replay-json",
        )
    )
    bundle_dir = store.export_bundle(tmp_path / "audit-bundle-json", ReceiptQuery(trace_id="trace:replay-json"))
    output_path = tmp_path / "replay.json"

    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "dualkey.replay",
            str(bundle_dir / "manifest.json"),
            "--trace-id",
            "trace:replay-json",
            "--format",
            "json",
            "--output",
            str(output_path),
        ],
        text=True,
        capture_output=True,
        check=True,
        env={**os.environ, "PYTHONPATH": str(SRC)},
    )

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert process.stdout == ""
    assert payload["source"]["kind"] == "bundle"
    assert payload["traces"][0]["trace_id"] == "trace:replay-json"
    assert payload["traces"][0]["events"][0]["delta_seconds"] == 0.0
    assert payload["traces"][0]["events"][0]["decision"] == "deny"
    assert payload["traces"][0]["events"][0]["action_summary"]["surface"] == "shell"


def test_replay_cli_supports_event_level_action_filters(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path / "filtered.sqlite")
    store.append(
        _sample_receipt(
            suffix="filtered-bash",
            trace_id="trace:filtered",
            status="waiting",
            decision="ask",
            created_at="2026-04-16T16:00:00Z",
            receipt_hash="hmac-sha256:filtered-bash",
            tool="bash",
            risk=["test", "safe"],
            metadata={"workspace": {"root": "/tmp/project"}, "session": "safe"},
        )
    )
    store.append(
        _sample_receipt(
            suffix="filtered-git",
            trace_id="trace:filtered",
            status="executed",
            decision="allow",
            created_at="2026-04-16T16:01:00Z",
            receipt_hash="hmac-sha256:filtered-git",
            tool="git",
            risk=["test", "dangerous"],
            metadata={"workspace": {"root": "/tmp/project"}, "branch": "main"},
        )
    )
    bundle_dir = store.export_bundle(tmp_path / "filtered-bundle", ReceiptQuery(trace_id="trace:filtered"))

    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "dualkey.replay",
            str(bundle_dir),
            "--trace-id",
            "trace:filtered",
            "--tool",
            "git",
            "--risk",
            "dangerous",
            "--target-contains",
            "filtered-git",
            "--metadata-path",
            "branch",
            "--metadata-contains",
            "main",
            "--show-metadata",
        ],
        text=True,
        capture_output=True,
        check=True,
        env={**os.environ, "PYTHONPATH": str(SRC)},
    )

    assert "tool=git" in process.stdout
    assert "filtered-git" in process.stdout
    assert "filtered-bash" not in process.stdout
    assert "metadata:" in process.stdout
    assert "branch=main" in process.stdout
    assert "workspace={root=/tmp/project}" in process.stdout
    assert "1. +0.0s 2026-04-16T16:01:00Z executed allow" in process.stdout


def test_replay_cli_can_export_html_viewer(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path / "viewer.sqlite")
    store.append(
        _sample_receipt(
            suffix="viewer-git",
            trace_id="trace:viewer",
            status="executed",
            decision="allow",
            created_at="2026-04-16T17:00:00Z",
            receipt_hash="hmac-sha256:viewer-git",
            tool="git",
            risk=["test", "dangerous"],
            metadata={"workspace": {"root": "/tmp/project"}, "branch": "release"},
        )
    )
    bundle_dir = store.export_bundle(tmp_path / "viewer-bundle", ReceiptQuery(trace_id="trace:viewer"))
    output_path = tmp_path / "audit-view.html"

    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "dualkey.replay",
            str(bundle_dir),
            "--trace-id",
            "trace:viewer",
            "--format",
            "html",
            "--output",
            str(output_path),
            "--show-metadata",
        ],
        text=True,
        capture_output=True,
        check=True,
        env={**os.environ, "PYTHONPATH": str(SRC)},
    )

    html = output_path.read_text(encoding="utf-8")
    assert process.stdout == ""
    assert "<title>DualKey Replay Viewer</title>" in html
    assert "Trace trace:viewer" in html
    assert "Filters &amp; Folding" in html
    assert 'id="filter-search"' in html
    assert 'id="filter-tool"' in html
    assert "Expand all traces" in html
    assert "Collapse all traces" in html
    assert 'data-trace-id="trace:viewer"' in html
    assert 'data-tool="git"' in html
    assert "tool=git" in html
    assert "branch=release" in html
    assert "workspace={root=/tmp/project}" in html
    assert "Backend" in html
