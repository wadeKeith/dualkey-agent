from __future__ import annotations

import argparse
from hashlib import sha256
import json
from pathlib import Path
from typing import Any

from dualkey.receipts import (
    ReceiptSigner,
    ReceiptStore,
    verify_bundle_manifest_payload,
    verify_receipt_payload,
)


def build_verify_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Verify DualKey receipt stores and audit bundles")
    parser.add_argument("source", help="Path to a receipt store, bundle directory, or bundle manifest.json")
    parser.add_argument("--signing-key", default=None, help="Override the HMAC signing key used for verification")
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="How to print verification results",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Write the rendered verification report to a file instead of stdout",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_verify_parser()
    args = parser.parse_args(argv)

    signer = ReceiptSigner(args.signing_key)
    result = verify_source(Path(args.source), signer=signer)
    output = _render_verification_result(result, output_format=args.format)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output, encoding="utf-8")
    elif output:
        print(output)
    return 0 if result["valid"] else 1


def verify_source(source: Path, *, signer: ReceiptSigner | None = None) -> dict[str, Any]:
    signer = signer or ReceiptSigner()
    if source.is_dir() or source.name == "manifest.json":
        return _verify_bundle_source(source, signer=signer)
    return _verify_store_source(source, signer=signer)


def _verify_store_source(source: Path, *, signer: ReceiptSigner) -> dict[str, Any]:
    result = _new_verification_result(kind="store", path=source)
    payloads = _read_payloads(source, result)
    _verify_receipts(payloads, result, signer=signer)
    result["receipt_count"] = len(payloads)
    result["valid"] = not result["errors"]
    return result


def _verify_bundle_source(source: Path, *, signer: ReceiptSigner) -> dict[str, Any]:
    bundle_dir = source if source.is_dir() else source.parent
    manifest_path = bundle_dir / "manifest.json" if source.is_dir() else source
    receipts_path = bundle_dir / "receipts.jsonl"
    result = _new_verification_result(kind="bundle", path=bundle_dir)
    result["bundle_dir"] = str(bundle_dir)
    result["manifest_path"] = str(manifest_path)
    result["receipts_path"] = str(receipts_path)

    manifest = _read_manifest(manifest_path, result)
    payloads = _read_payloads(receipts_path, result)
    _verify_receipts(payloads, result, signer=signer)
    result["receipt_count"] = len(payloads)

    if manifest is not None:
        signature_valid = verify_bundle_manifest_payload(manifest, signer=signer)
        result["manifest_signature_valid"] = signature_valid
        if not signature_valid:
            result["errors"].append("bundle manifest signature is invalid or missing")
        _verify_bundle_files(bundle_dir, manifest, result)
        _verify_bundle_summary(payloads, manifest, result)

    result["valid"] = not result["errors"]
    return result


def _new_verification_result(*, kind: str, path: Path) -> dict[str, Any]:
    return {
        "kind": kind,
        "path": str(path),
        "valid": False,
        "receipt_count": 0,
        "verified_receipts": 0,
        "invalid_receipts": [],
        "manifest_signature_valid": None,
        "bundle_files": {},
        "errors": [],
        "warnings": [],
    }


def _read_manifest(path: Path, result: dict[str, Any]) -> dict[str, Any] | None:
    if not path.exists():
        result["errors"].append(f"bundle manifest not found: {path}")
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        result["errors"].append(f"failed to read bundle manifest {path}: {exc}")
        return None
    if not isinstance(payload, dict):
        result["errors"].append(f"bundle manifest is not a JSON object: {path}")
        return None
    return payload


def _read_payloads(path: Path, result: dict[str, Any]) -> list[dict[str, Any]]:
    if not path.exists():
        result["errors"].append(f"receipt source not found: {path}")
        return []
    try:
        payloads = ReceiptStore(path).read_payloads()
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        result["errors"].append(f"failed to read receipt source {path}: {exc}")
        return []
    return [payload for payload in payloads if isinstance(payload, dict)]


def _verify_receipts(payloads: list[dict[str, Any]], result: dict[str, Any], *, signer: ReceiptSigner) -> None:
    verified = 0
    invalid: list[dict[str, Any]] = []
    for index, payload in enumerate(payloads, start=1):
        if verify_receipt_payload(payload, signer=signer):
            verified += 1
            continue
        invalid_payload = {
            "index": index,
            "trace_id": payload.get("trace_id"),
            "receipt_hash": payload.get("receipt_hash"),
        }
        invalid.append(invalid_payload)
        result["errors"].append(
            "invalid receipt signature"
            f" at index {index}"
            f" trace_id={payload.get('trace_id') or '-'}"
            f" receipt_hash={payload.get('receipt_hash') or '-'}"
        )
    result["verified_receipts"] = verified
    result["invalid_receipts"] = invalid


def _verify_bundle_files(bundle_dir: Path, manifest: dict[str, Any], result: dict[str, Any]) -> None:
    files = manifest.get("files")
    file_hashes = manifest.get("file_hashes")
    if not isinstance(files, dict):
        result["errors"].append("bundle manifest is missing files mapping")
        return
    if not isinstance(file_hashes, dict):
        result["errors"].append("bundle manifest is missing file_hashes mapping")
        return

    for alias, relative_path in files.items():
        expected_hash = file_hashes.get(alias)
        file_path = bundle_dir / str(relative_path)
        entry = {
            "path": str(file_path),
            "exists": file_path.exists(),
            "expected_hash": expected_hash,
            "actual_hash": None,
            "valid": False,
        }
        if alias == "manifest":
            entry["valid"] = file_path.exists()
            result["bundle_files"][alias] = entry
            continue
        if not file_path.exists():
            result["errors"].append(f"bundle file missing for {alias}: {file_path}")
            result["bundle_files"][alias] = entry
            continue
        actual_hash = _hash_file(file_path)
        entry["actual_hash"] = actual_hash
        entry["valid"] = expected_hash == actual_hash
        result["bundle_files"][alias] = entry
        if expected_hash is None:
            result["errors"].append(f"bundle manifest is missing expected hash for {alias}")
        elif expected_hash != actual_hash:
            result["errors"].append(
                f"bundle file hash mismatch for {alias}: expected {expected_hash}, got {actual_hash}"
            )


def _verify_bundle_summary(payloads: list[dict[str, Any]], manifest: dict[str, Any], result: dict[str, Any]) -> None:
    trace_ids = _expected_trace_ids(payloads)
    expected = {
        "receipt_count": len(payloads),
        "trace_count": len(trace_ids),
        "trace_ids": trace_ids,
        "action_hashes": _unique_values(payloads, field_name="action_hash"),
        "action_context": {
            "actors": _unique_action_summary_values(payloads, "actor"),
            "surfaces": _unique_action_summary_values(payloads, "surface"),
            "tools": _unique_action_summary_values(payloads, "tool"),
        },
    }
    for key in ("receipt_count", "trace_count", "trace_ids", "action_hashes"):
        if manifest.get(key) != expected[key]:
            result["errors"].append(
                f"bundle manifest {key} mismatch: expected {expected[key]!r}, got {manifest.get(key)!r}"
            )
    if manifest.get("action_context") != expected["action_context"]:
        result["errors"].append(
            "bundle manifest action_context mismatch:"
            f" expected {expected['action_context']!r}, got {manifest.get('action_context')!r}"
        )


def _unique_values(payloads: list[dict[str, Any]], *, field_name: str) -> list[str]:
    values = dict.fromkeys(
        str(payload.get(field_name))
        for payload in payloads
        if payload.get(field_name)
    )
    return list(values)


def _expected_trace_ids(payloads: list[dict[str, Any]]) -> list[str]:
    trace_ids: list[str] = []
    seen: set[str] = set()
    anonymous_count = 0
    for payload in payloads:
        trace_id = payload.get("trace_id")
        if isinstance(trace_id, str) and trace_id:
            if trace_id not in seen:
                seen.add(trace_id)
                trace_ids.append(trace_id)
            continue
        anonymous_count += 1
        trace_ids.append(f"(no-trace-{anonymous_count})")
    return trace_ids


def _unique_action_summary_values(payloads: list[dict[str, Any]], key: str) -> list[str]:
    values = dict.fromkeys(
        str(summary.get(key))
        for payload in payloads
        if isinstance(summary := payload.get("action_summary"), dict) and summary.get(key)
    )
    return list(values)


def _hash_file(path: Path) -> str:
    return "sha256:" + sha256(path.read_bytes()).hexdigest()


def _render_verification_result(result: dict[str, Any], *, output_format: str) -> str:
    if output_format == "json":
        return json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True)
    return _render_verification_text(result)


def _render_verification_text(result: dict[str, Any]) -> str:
    lines = [
        f"Verification source: {result['kind']}",
        f"Path: {result['path']}",
        f"Status: {'valid' if result['valid'] else 'invalid'}",
        f"Receipts: {result['verified_receipts']}/{result['receipt_count']} verified",
    ]
    if result.get("manifest_signature_valid") is not None:
        lines.append(
            "Manifest signature: "
            + ("valid" if result["manifest_signature_valid"] else "invalid")
        )
    bundle_files = result.get("bundle_files") or {}
    if bundle_files:
        lines.append("Bundle files:")
        for alias, entry in bundle_files.items():
            status = "ok" if entry.get("valid") else "invalid"
            lines.append(f"- {alias}: {status}")
    warnings = result.get("warnings") or []
    if warnings:
        lines.append("Warnings:")
        lines.extend(f"- {warning}" for warning in warnings)
    errors = result.get("errors") or []
    if errors:
        lines.append("Errors:")
        lines.extend(f"- {error}" for error in errors)
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
