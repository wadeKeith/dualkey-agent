from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from dualkey.models import ActionEnvelope, AuthorizationResult, PolicyOutcome
from dualkey.receipts import ReceiptStore, build_receipt


def _build_valid_receipt(*, suffix: str, trace_id: str | None = None):
    action = ActionEnvelope(
        actor="dualkey-ci",
        surface="shell",
        tool="bash",
        intent="execute",
        target=f"/tmp/{suffix}",
        args={"command": f"echo {suffix}"},
        risk=["test"],
        session_id=f"session:{suffix}",
        trace_id=trace_id or f"trace:{suffix}",
        metadata={"source": "verify-smoke", "workspace": {"root": "/tmp/project"}},
    )
    authorization = AuthorizationResult(
        allowed=True,
        final_decision="allow",
        policy_outcome=PolicyOutcome(
            decision="allow",
            rule_id="ci_smoke_rule",
            reason="verify smoke fixture",
        ),
    )
    return build_receipt(
        action=action,
        authorization=authorization,
        status="executed",
        result=f"ran {suffix}",
    )


def _verify_command() -> list[str]:
    if cli := shutil.which("dualkey-verify"):
        return [cli]
    return [sys.executable, "-m", "dualkey.verify"]


def _run_verify(source: Path) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
    process = subprocess.run(
        [*_verify_command(), str(source), "--format", "json"],
        text=True,
        capture_output=True,
        check=False,
    )
    try:
        payload = json.loads(process.stdout)
    except json.JSONDecodeError as exc:  # pragma: no cover - only used in CI failure mode
        raise SystemExit(
            "dualkey-verify did not return JSON output\n"
            f"command: {' '.join([*_verify_command(), str(source), '--format', 'json'])}\n"
            f"stdout: {process.stdout}\n"
            f"stderr: {process.stderr}\n"
            f"error: {exc}"
        ) from exc
    return process, payload


def _expect_valid(source: Path) -> None:
    process, payload = _run_verify(source)
    if process.returncode != 0 or payload.get("valid") is not True:
        raise SystemExit(
            f"expected valid verification result for {source}\n"
            f"returncode={process.returncode}\n"
            f"payload={json.dumps(payload, indent=2, sort_keys=True)}\n"
            f"stderr={process.stderr}"
        )


def _expect_invalid(source: Path) -> None:
    process, payload = _run_verify(source)
    if process.returncode == 0 or payload.get("valid") is not False:
        raise SystemExit(
            f"expected invalid verification result for {source}\n"
            f"returncode={process.returncode}\n"
            f"payload={json.dumps(payload, indent=2, sort_keys=True)}\n"
            f"stderr={process.stderr}"
        )


def _tamper_jsonl_field(path: Path, field_name: str, value: str) -> None:
    payloads = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    payloads[0][field_name] = value
    path.write_text(
        "\n".join(json.dumps(payload, sort_keys=True) for payload in payloads) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    with TemporaryDirectory(prefix="dualkey-verify-smoke-") as tmpdir:
        root = Path(tmpdir)

        valid_store = ReceiptStore(root / "receipts.jsonl")
        valid_store.append(_build_valid_receipt(suffix="store-ok"))
        _expect_valid(valid_store.path)

        tampered_store = ReceiptStore(root / "receipts-tampered.jsonl")
        tampered_store.append(_build_valid_receipt(suffix="store-tampered"))
        _tamper_jsonl_field(tampered_store.path, "decision", "deny")
        _expect_invalid(tampered_store.path)

        bundle_source = ReceiptStore(root / "bundle-source.jsonl")
        bundle_source.append(_build_valid_receipt(suffix="bundle-1", trace_id="trace:bundle-ok"))
        bundle_source.append(_build_valid_receipt(suffix="bundle-2", trace_id="trace:bundle-ok"))
        bundle_dir = bundle_source.export_bundle(root / "audit-bundle")
        _expect_valid(bundle_dir / "manifest.json")

        tampered_bundle_source = ReceiptStore(root / "bundle-tampered-source.jsonl")
        tampered_bundle_source.append(
            _build_valid_receipt(suffix="bundle-tampered", trace_id="trace:bundle-tampered")
        )
        tampered_bundle_dir = tampered_bundle_source.export_bundle(root / "audit-bundle-tampered")
        _tamper_jsonl_field(tampered_bundle_dir / "receipts.jsonl", "result_preview", "tampered result preview")
        _expect_invalid(tampered_bundle_dir)

    print("dualkey-verify smoke checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
