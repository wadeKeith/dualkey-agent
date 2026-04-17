from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

from dualkey.models import ActionEnvelope, AuthorizationResult, PolicyOutcome, Receipt
from dualkey.receipts import ReceiptQuery, ReceiptSettings, ReceiptStore, build_receipt


def _sample_receipt(
    *,
    suffix: str,
    settings: ReceiptSettings | None = None,
    result: str | None = None,
    error: str | None = None,
) -> Receipt:
    action = ActionEnvelope(
        actor="dualkey-test",
        surface="shell",
        tool="bash",
        intent="execute",
        target=f"/tmp/{suffix}",
        args={"command": f"echo {suffix}"},
        risk=["test"],
        session_id="sess:test",
        trace_id=f"trace:{suffix}",
        metadata={"suffix": suffix},
    )
    authorization = AuthorizationResult(
        allowed=True,
        final_decision="allow",
        policy_outcome=PolicyOutcome(
            decision="allow",
            rule_id="test_rule",
            reason="unit test fixture",
        ),
    )
    return build_receipt(
        action=action,
        authorization=authorization,
        status="executed",
        result=result or f"ran {suffix}",
        error=error,
        settings=settings,
    )


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "sdk" / "python" / "src"


def test_receipt_store_keeps_jsonl_behavior(tmp_path: Path) -> None:
    path = tmp_path / "receipts.jsonl"
    store = ReceiptStore(path)

    store.append(_sample_receipt(suffix="jsonl-one"))
    store.append(_sample_receipt(suffix="jsonl-two"))

    assert store.backend_name == "jsonl"
    payloads = store.read_payloads()
    assert [payload["trace_id"] for payload in payloads] == [
        "trace:jsonl-one",
        "trace:jsonl-two",
    ]

    lines = path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["status"] == "executed"


def test_receipt_store_uses_sqlite_for_db_paths(tmp_path: Path) -> None:
    path = tmp_path / "receipts.sqlite"
    store = ReceiptStore(path)

    store.append(_sample_receipt(suffix="sqlite"))

    assert store.backend_name == "sqlite"
    assert path.exists()

    payloads = store.read_payloads()
    assert len(payloads) == 1
    assert payloads[0]["trace_id"] == "trace:sqlite"

    with sqlite3.connect(path) as connection:
        row = connection.execute(
            """
            SELECT decision, status, trace_id, action_hash, payload_json
            FROM receipts
            """
        ).fetchone()
        assert row is not None
        assert row[0] == "allow"
        assert row[1] == "executed"
        assert row[2] == "trace:sqlite"
        assert row[3].startswith("sha256:")
        assert json.loads(row[4])["receipt_hash"].startswith("hmac-sha256:")

        index_names = {
            result[0]
            for result in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'receipts'"
            ).fetchall()
        }

    assert {
        "idx_receipts_created_at",
        "idx_receipts_trace_id",
        "idx_receipts_action_hash",
        "idx_receipts_status",
        "idx_receipts_decision",
        "idx_receipts_policy_match",
    }.issubset(index_names)


def test_build_receipt_redacts_sensitive_preview_and_error() -> None:
    receipt = _sample_receipt(
        suffix="redaction",
        settings=ReceiptSettings(redact_sensitive_values=True),
        result="token=supersecret sk-abc1234567890",
        error="Authorization: Bearer topsecretvalue",
    )

    assert "[REDACTED]" in receipt.result_preview
    assert "supersecret" not in receipt.result_preview
    assert "sk-abc1234567890" not in receipt.result_preview
    assert receipt.error == "Authorization: Bearer [REDACTED]"


def test_receipt_store_retention_keeps_latest_jsonl_entries(tmp_path: Path) -> None:
    path = tmp_path / "retained.jsonl"
    store = ReceiptStore(
        path,
        settings=ReceiptSettings(redact_sensitive_values=False, max_receipts=1),
    )

    store.append(_sample_receipt(suffix="keep-old"))
    store.append(_sample_receipt(suffix="keep-new"))

    payloads = store.read_payloads()
    assert [payload["trace_id"] for payload in payloads] == ["trace:keep-new"]


def test_receipt_store_retention_drops_old_sqlite_entries(tmp_path: Path) -> None:
    path = tmp_path / "retained.sqlite"
    store = ReceiptStore(
        path,
        settings=ReceiptSettings(redact_sensitive_values=False, retention_days=30),
    )
    stale = _sample_receipt(suffix="stale")
    stale = Receipt(
        **{
            **stale.to_payload(),
            "created_at": "2000-01-01T00:00:00Z",
            "receipt_hash": "hmac-sha256:stale",
        }
    )

    store.append(stale)
    store.append(_sample_receipt(suffix="fresh"))

    payloads = store.read_payloads()
    assert [payload["trace_id"] for payload in payloads] == ["trace:fresh"]


def test_receipt_store_query_payloads_work_for_jsonl_and_sqlite(tmp_path: Path) -> None:
    jsonl_store = ReceiptStore(tmp_path / "query.jsonl")
    sqlite_store = ReceiptStore(tmp_path / "query.sqlite")
    receipts = [
        _sample_receipt(suffix="alpha"),
        _sample_receipt(suffix="beta"),
        _sample_receipt(suffix="gamma"),
    ]
    receipts[1] = Receipt(
        **{
            **receipts[1].to_payload(),
            "status": "blocked",
            "decision": "deny",
            "trace_id": "trace:shared",
            "receipt_hash": "hmac-sha256:beta",
        }
    )
    receipts[2] = Receipt(
        **{
            **receipts[2].to_payload(),
            "status": "executed",
            "decision": "allow",
            "trace_id": "trace:shared",
            "policy_match": "shared_rule",
            "receipt_hash": "hmac-sha256:gamma",
        }
    )

    for store in (jsonl_store, sqlite_store):
        for receipt in receipts:
            store.append(receipt)

    query = ReceiptQuery(trace_id="trace:shared", descending=True, limit=1)
    jsonl_payloads = jsonl_store.query_payloads(query)
    sqlite_payloads = sqlite_store.query_payloads(query)

    assert len(jsonl_payloads) == len(sqlite_payloads) == 1
    assert jsonl_payloads[0]["trace_id"] == sqlite_payloads[0]["trace_id"] == "trace:shared"
    assert jsonl_payloads[0]["policy_match"] == sqlite_payloads[0]["policy_match"] == "shared_rule"


def test_receipt_query_cli_filters_by_trace_id(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path / "cli.sqlite")
    store.append(_sample_receipt(suffix="cli-one"))
    matched = Receipt(
        **{
            **_sample_receipt(suffix="cli-two").to_payload(),
            "trace_id": "trace:cli-shared",
            "receipt_hash": "hmac-sha256:cli-two",
        }
    )
    store.append(matched)

    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "dualkey.receipts",
            str(store.path),
            "--trace-id",
            "trace:cli-shared",
            "--format",
            "json",
        ],
        text=True,
        capture_output=True,
        check=True,
        env={**os.environ, "PYTHONPATH": str(SRC)},
    )

    payloads = json.loads(process.stdout)
    assert len(payloads) == 1
    assert payloads[0]["trace_id"] == "trace:cli-shared"


def test_receipt_store_builds_trace_timeline(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path / "timeline.jsonl")
    waiting = Receipt(
        **{
            **_sample_receipt(suffix="timeline-1").to_payload(),
            "trace_id": "trace:timeline",
            "status": "waiting",
            "decision": "ask",
            "created_at": "2026-04-16T10:00:00Z",
            "receipt_hash": "hmac-sha256:timeline-1",
        }
    )
    approved = Receipt(
        **{
            **_sample_receipt(suffix="timeline-2").to_payload(),
            "trace_id": "trace:timeline",
            "status": "executed",
            "decision": "ask->approved",
            "created_at": "2026-04-16T10:01:00Z",
            "receipt_hash": "hmac-sha256:timeline-2",
        }
    )
    store.append(waiting)
    store.append(approved)

    traces = store.build_traces(ReceiptQuery(trace_id="trace:timeline"))

    assert len(traces) == 1
    assert traces[0].trace_id == "trace:timeline"
    assert traces[0].started_at == "2026-04-16T10:00:00Z"
    assert traces[0].ended_at == "2026-04-16T10:01:00Z"
    assert [payload["status"] for payload in traces[0].receipts] == ["waiting", "executed"]


def test_receipt_query_cli_can_render_timeline(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path / "timeline.sqlite")
    first = Receipt(
        **{
            **_sample_receipt(suffix="timeline-cli-1").to_payload(),
            "trace_id": "trace:timeline-cli",
            "status": "waiting",
            "decision": "ask",
            "created_at": "2026-04-16T10:00:00Z",
            "receipt_hash": "hmac-sha256:timeline-cli-1",
        }
    )
    second = Receipt(
        **{
            **_sample_receipt(suffix="timeline-cli-2").to_payload(),
            "trace_id": "trace:timeline-cli",
            "status": "executed",
            "decision": "ask->approved",
            "created_at": "2026-04-16T10:01:00Z",
            "receipt_hash": "hmac-sha256:timeline-cli-2",
        }
    )
    store.append(first)
    store.append(second)

    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "dualkey.receipts",
            str(store.path),
            "--trace-id",
            "trace:timeline-cli",
            "--format",
            "timeline",
        ],
        text=True,
        capture_output=True,
        check=True,
        env={**os.environ, "PYTHONPATH": str(SRC)},
    )

    assert "trace_id: trace:timeline-cli" in process.stdout
    assert "1. 2026-04-16T10:00:00Z waiting ask" in process.stdout
    assert "2. 2026-04-16T10:01:00Z executed ask->approved" in process.stdout


def test_receipt_store_can_render_markdown_report(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path / "report.sqlite")
    first = Receipt(
        **{
            **_sample_receipt(suffix="report-1").to_payload(),
            "trace_id": "trace:report",
            "status": "waiting",
            "decision": "ask",
            "policy_match": "prod_write_requires_human",
            "created_at": "2026-04-16T10:00:00Z",
            "receipt_hash": "hmac-sha256:report-1",
        }
    )
    second = Receipt(
        **{
            **_sample_receipt(suffix="report-2").to_payload(),
            "trace_id": "trace:report",
            "status": "executed",
            "decision": "ask->approved",
            "policy_match": "prod_write_requires_human",
            "approved_by": "human:alice",
            "approved_at": "2026-04-16T10:00:30Z",
            "created_at": "2026-04-16T10:01:00Z",
            "receipt_hash": "hmac-sha256:report-2",
        }
    )
    store.append(first)
    store.append(second)

    report = store.render_report(ReceiptQuery(trace_id="trace:report"))

    assert report.startswith("# DualKey Audit Report")
    assert "## Trace `trace:report`" in report
    assert "- traces: 1" in report
    assert "- ask: 1" in report
    assert "- ask->approved: 1" in report
    assert "context: `actor=dualkey-test surface=shell tool=bash intent=execute target=/tmp/report-1 risk=test`" in report
    assert "| 2 | 2026-04-16T10:01:00Z | executed | ask->approved | prod_write_requires_human | human:alice | 2026-04-16T10:00:30Z |" in report


def test_receipt_query_cli_can_export_markdown_report(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path / "report-cli.sqlite")
    receipt = Receipt(
        **{
            **_sample_receipt(suffix="report-cli").to_payload(),
            "trace_id": "trace:report-cli",
            "status": "blocked",
            "decision": "deny",
            "policy_match": "secret_write_denied",
            "created_at": "2026-04-16T11:00:00Z",
            "receipt_hash": "hmac-sha256:report-cli",
        }
    )
    store.append(receipt)
    output_path = tmp_path / "audit-report.md"

    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "dualkey.receipts",
            str(store.path),
            "--trace-id",
            "trace:report-cli",
            "--format",
            "markdown",
            "--output",
            str(output_path),
        ],
        text=True,
        capture_output=True,
        check=True,
        env={**os.environ, "PYTHONPATH": str(SRC)},
    )

    assert process.stdout == ""
    report = output_path.read_text(encoding="utf-8")
    assert report.startswith("# DualKey Audit Report")
    assert "## Trace `trace:report-cli`" in report
    assert "- deny: 1" in report
    assert "secret_write_denied" in report


def test_receipt_store_can_export_bundle(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path / "bundle.sqlite")
    first = Receipt(
        **{
            **_sample_receipt(suffix="bundle-1").to_payload(),
            "trace_id": "trace:bundle",
            "status": "waiting",
            "decision": "ask",
            "policy_match": "prod_write_requires_human",
            "created_at": "2026-04-16T12:00:00Z",
            "receipt_hash": "hmac-sha256:bundle-1",
        }
    )
    second = Receipt(
        **{
            **_sample_receipt(suffix="bundle-2").to_payload(),
            "trace_id": "trace:bundle",
            "status": "executed",
            "decision": "ask->approved",
            "policy_match": "prod_write_requires_human",
            "approved_by": "human:alice",
            "approved_at": "2026-04-16T12:00:20Z",
            "created_at": "2026-04-16T12:01:00Z",
            "receipt_hash": "hmac-sha256:bundle-2",
        }
    )
    store.append(first)
    store.append(second)

    bundle_dir = store.export_bundle(tmp_path / "audit-bundle", ReceiptQuery(trace_id="trace:bundle"))

    manifest = json.loads((bundle_dir / "manifest.json").read_text(encoding="utf-8"))
    report = (bundle_dir / "report.md").read_text(encoding="utf-8")
    timeline = (bundle_dir / "timeline.txt").read_text(encoding="utf-8")
    receipts_lines = (bundle_dir / "receipts.jsonl").read_text(encoding="utf-8").splitlines()

    assert bundle_dir.is_dir()
    assert manifest["trace_count"] == 1
    assert manifest["receipt_count"] == 2
    assert manifest["trace_ids"] == ["trace:bundle"]
    assert manifest["action_context"]["surfaces"] == ["shell"]
    assert manifest["action_context"]["tools"] == ["bash"]
    assert manifest["format_version"] == "dualkey.bundle.v1"
    assert manifest["files"]["report"] == "report.md"
    assert manifest["manifest_signature"].startswith("hmac-sha256:")
    assert manifest["file_hashes"]["report"].startswith("sha256:")
    assert manifest["file_hashes"]["timeline"].startswith("sha256:")
    assert manifest["file_hashes"]["receipts"].startswith("sha256:")
    assert report.startswith("# DualKey Audit Report")
    assert "## Trace `trace:bundle`" in report
    assert "trace_id: trace:bundle" in timeline
    assert len(receipts_lines) == 2


def test_receipt_query_cli_can_export_bundle(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path / "bundle-cli.sqlite")
    receipt = Receipt(
        **{
            **_sample_receipt(suffix="bundle-cli").to_payload(),
            "trace_id": "trace:bundle-cli",
            "status": "blocked",
            "decision": "deny",
            "policy_match": "secret_write_denied",
            "created_at": "2026-04-16T13:00:00Z",
            "receipt_hash": "hmac-sha256:bundle-cli",
        }
    )
    store.append(receipt)
    output_dir = tmp_path / "bundle-cli-output"

    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "dualkey.receipts",
            str(store.path),
            "--trace-id",
            "trace:bundle-cli",
            "--format",
            "bundle",
            "--output",
            str(output_dir),
        ],
        text=True,
        capture_output=True,
        check=True,
        env={**os.environ, "PYTHONPATH": str(SRC)},
    )

    manifest = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    assert process.stdout == ""
    assert (output_dir / "report.md").exists()
    assert (output_dir / "timeline.txt").exists()
    assert (output_dir / "receipts.jsonl").exists()
    assert manifest["trace_ids"] == ["trace:bundle-cli"]
    assert manifest["query"]["trace_id"] == "trace:bundle-cli"
    assert manifest["manifest_signature"].startswith("hmac-sha256:")
