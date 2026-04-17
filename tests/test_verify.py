from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

from dualkey.models import ActionEnvelope, AuthorizationResult, PolicyOutcome
from dualkey.receipts import ReceiptStore, build_receipt


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "sdk" / "python" / "src"


def _valid_receipt(*, suffix: str, trace_id: str | None = None):
    action = ActionEnvelope(
        actor="dualkey-test",
        surface="shell",
        tool="bash",
        intent="execute",
        target=f"/tmp/{suffix}",
        args={"command": f"echo {suffix}"},
        risk=["test"],
        session_id=f"sess:{suffix}",
        trace_id=trace_id or f"trace:{suffix}",
        metadata={"suffix": suffix, "workspace": {"root": "/tmp/project"}},
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
        result=f"ran {suffix}",
    )


def _run_verify(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "dualkey.verify",
            *args,
        ],
        text=True,
        capture_output=True,
        env={**os.environ, "PYTHONPATH": str(SRC), **(env or {})},
        check=False,
    )


def test_verify_cli_accepts_valid_store(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path / "receipts.jsonl")
    store.append(_valid_receipt(suffix="store-ok"))

    process = _run_verify(str(store.path), "--format", "json")

    payload = json.loads(process.stdout)
    assert process.returncode == 0
    assert payload["valid"] is True
    assert payload["receipt_count"] == 1
    assert payload["verified_receipts"] == 1
    assert payload["errors"] == []


def test_verify_cli_rejects_tampered_store(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path / "tampered.jsonl")
    store.append(_valid_receipt(suffix="store-tampered"))

    payloads = [json.loads(line) for line in store.path.read_text(encoding="utf-8").splitlines() if line.strip()]
    payloads[0]["decision"] = "deny"
    store.path.write_text(
        "\n".join(json.dumps(payload, sort_keys=True) for payload in payloads) + "\n",
        encoding="utf-8",
    )

    process = _run_verify(str(store.path), "--format", "json")

    payload = json.loads(process.stdout)
    assert process.returncode == 1
    assert payload["valid"] is False
    assert payload["verified_receipts"] == 0
    assert any("invalid receipt signature" in error for error in payload["errors"])


def test_verify_cli_accepts_valid_bundle(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path / "bundle-source.jsonl")
    store.append(_valid_receipt(suffix="bundle-1", trace_id="trace:bundle-ok"))
    store.append(_valid_receipt(suffix="bundle-2", trace_id="trace:bundle-ok"))
    bundle_dir = store.export_bundle(tmp_path / "audit-bundle")

    process = _run_verify(str(bundle_dir / "manifest.json"), "--format", "json")

    payload = json.loads(process.stdout)
    assert process.returncode == 0
    assert payload["valid"] is True
    assert payload["manifest_signature_valid"] is True
    assert payload["bundle_files"]["report"]["valid"] is True
    assert payload["bundle_files"]["timeline"]["valid"] is True
    assert payload["bundle_files"]["receipts"]["valid"] is True


def test_verify_cli_rejects_tampered_bundle(tmp_path: Path) -> None:
    store = ReceiptStore(tmp_path / "bundle-tampered-source.jsonl")
    store.append(_valid_receipt(suffix="bundle-tampered", trace_id="trace:bundle-tampered"))
    bundle_dir = store.export_bundle(tmp_path / "audit-bundle-tampered")
    receipts_path = bundle_dir / "receipts.jsonl"

    payloads = [json.loads(line) for line in receipts_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    payloads[0]["result_preview"] = "tampered result preview"
    receipts_path.write_text(
        "\n".join(json.dumps(payload, sort_keys=True) for payload in payloads) + "\n",
        encoding="utf-8",
    )

    process = _run_verify(str(bundle_dir), "--format", "json")

    payload = json.loads(process.stdout)
    assert process.returncode == 1
    assert payload["valid"] is False
    assert payload["manifest_signature_valid"] is True
    assert payload["bundle_files"]["receipts"]["valid"] is False
    assert any("bundle file hash mismatch for receipts" in error for error in payload["errors"])
    assert any("invalid receipt signature" in error for error in payload["errors"])
