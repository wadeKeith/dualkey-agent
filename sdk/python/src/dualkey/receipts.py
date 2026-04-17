from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
from typing import Any

from dualkey.models import ActionEnvelope, AuthorizationResult, Receipt, utc_now


class ReceiptSigner:
    def __init__(self, signing_key: str | bytes | None = None) -> None:
        key = signing_key or os.environ.get("DUALKEY_SIGNING_KEY", "dualkey-dev-key")
        self._key = key.encode("utf-8") if isinstance(key, str) else key

    def sign(self, payload: dict[str, Any]) -> str:
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        digest = hmac.new(self._key, body, sha256).hexdigest()
        return f"hmac-sha256:{digest}"

    def verify(self, payload: dict[str, Any], signature: str | None) -> bool:
        if not signature:
            return False
        return hmac.compare_digest(self.sign(payload), str(signature))


SQLITE_SUFFIXES = {".db", ".sqlite", ".sqlite3"}
FALSE_VALUES = {"0", "false", "no", "off"}
SENSITIVE_TEXT_PATTERNS = (
    (
        re.compile(r"(?i)\b(api[_-]?key|token|secret|password)\b\s*[:=]\s*([^\s,;]+)"),
        lambda match: f"{match.group(1)}=[REDACTED]",
    ),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{8,}"), "Bearer [REDACTED]"),
    (re.compile(r"\b(sk-[A-Za-z0-9]{10,}|ghp_[A-Za-z0-9]{20,})\b"), "[REDACTED_TOKEN]"),
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
            re.MULTILINE,
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
)


@dataclass(slots=True)
class ReceiptSettings:
    redact_sensitive_values: bool = True
    retention_days: int | None = None
    max_receipts: int | None = None

    @classmethod
    def from_env(cls) -> "ReceiptSettings":
        return cls(
            redact_sensitive_values=_env_flag("DUALKEY_RECEIPT_REDACTION", default=True),
            retention_days=_env_int("DUALKEY_RECEIPT_RETENTION_DAYS"),
            max_receipts=_env_int("DUALKEY_RECEIPT_MAX_RECEIPTS"),
        )


@dataclass(slots=True)
class ReceiptQuery:
    trace_id: str | None = None
    action_hash: str | None = None
    status: str | None = None
    decision: str | None = None
    policy_match: str | None = None
    limit: int | None = None
    descending: bool = False


@dataclass(slots=True)
class ReceiptTrace:
    trace_id: str
    started_at: str | None
    ended_at: str | None
    receipts: list[dict[str, Any]]
    action_hashes: list[str]


class ReceiptStore:
    def __init__(
        self,
        path: str | Path = ".dualkey/receipts.jsonl",
        *,
        settings: ReceiptSettings | None = None,
    ) -> None:
        self._path = Path(path)
        self._settings = settings or ReceiptSettings.from_env()
        self._backend: _BaseReceiptBackend = _build_receipt_backend(self._path, self._settings)

    @property
    def path(self) -> Path:
        return self._path

    @path.setter
    def path(self, value: str | Path) -> None:
        self._path = Path(value)
        self._backend = _build_receipt_backend(self._path, self._settings)

    @property
    def settings(self) -> ReceiptSettings:
        return self._settings

    @settings.setter
    def settings(self, value: ReceiptSettings) -> None:
        self._settings = value
        self._backend = _build_receipt_backend(self._path, self._settings)

    def append(self, receipt: Receipt) -> None:
        self._backend.append(receipt)

    @property
    def backend_name(self) -> str:
        return self._backend.name

    def read_payloads(self) -> list[dict[str, Any]]:
        return self._backend.read_payloads()

    def query_payloads(self, query: ReceiptQuery | None = None) -> list[dict[str, Any]]:
        return self._backend.query_payloads(query or ReceiptQuery())

    def build_traces(self, query: ReceiptQuery | None = None) -> list[ReceiptTrace]:
        return _build_receipt_traces(self.query_payloads(query), descending=(query or ReceiptQuery()).descending)

    def render_report(self, query: ReceiptQuery | None = None) -> str:
        query = query or ReceiptQuery()
        return _render_receipt_markdown_report(self.build_traces(query), descending=query.descending)

    def export_bundle(
        self,
        output_dir: str | Path,
        query: ReceiptQuery | None = None,
        *,
        signer: ReceiptSigner | None = None,
    ) -> Path:
        query = query or ReceiptQuery()
        payloads = self.query_payloads(query)
        traces = _build_receipt_traces(payloads, descending=query.descending)
        bundle_dir = Path(output_dir)
        bundle_dir.mkdir(parents=True, exist_ok=True)
        signer = signer or ReceiptSigner()

        report_path = bundle_dir / "report.md"
        timeline_path = bundle_dir / "timeline.txt"
        receipts_path = bundle_dir / "receipts.jsonl"
        manifest_path = bundle_dir / "manifest.json"

        report_text = _render_receipt_markdown_report(traces, descending=query.descending)
        timeline_text = _render_receipt_timeline(traces)
        receipts_text = _render_query_results(payloads, output_format="jsonl", descending=query.descending)

        report_path.write_text(report_text, encoding="utf-8")
        timeline_path.write_text(timeline_text, encoding="utf-8")
        receipts_path.write_text(receipts_text, encoding="utf-8")

        files = {
            "report": report_path.name,
            "timeline": timeline_path.name,
            "receipts": receipts_path.name,
            "manifest": manifest_path.name,
        }
        file_hashes = {
            "report": _hash_file(report_path),
            "timeline": _hash_file(timeline_path),
            "receipts": _hash_file(receipts_path),
        }
        manifest_body = _build_bundle_manifest(
            backend_name=self.backend_name,
            query=query,
            traces=traces,
            payloads=payloads,
            files=files,
            file_hashes=file_hashes,
        )
        manifest = {
            **manifest_body,
            "manifest_signature": sign_bundle_manifest_payload(manifest_body, signer=signer),
        }
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return bundle_dir


class _BaseReceiptBackend:
    name = "unknown"

    def append(self, receipt: Receipt) -> None:
        raise NotImplementedError

    def read_payloads(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    def query_payloads(self, query: ReceiptQuery) -> list[dict[str, Any]]:
        raise NotImplementedError


class _JsonlReceiptBackend(_BaseReceiptBackend):
    name = "jsonl"

    def __init__(self, path: Path, settings: ReceiptSettings) -> None:
        self.path = path
        self.settings = settings

    def append(self, receipt: Receipt) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(receipt.to_payload(), sort_keys=True))
            handle.write("\n")
        self._apply_retention()

    def read_payloads(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        return [
            json.loads(line)
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def query_payloads(self, query: ReceiptQuery) -> list[dict[str, Any]]:
        payloads = self.read_payloads()
        payloads = [
            payload
            for payload in payloads
            if _payload_matches_query(payload, query)
        ]
        payloads.sort(
            key=lambda payload: (
                str(payload.get("created_at", "")),
                str(payload.get("receipt_hash", "")),
            ),
            reverse=query.descending,
        )
        if query.limit is not None:
            return payloads[: query.limit]
        return payloads

    def _apply_retention(self) -> None:
        if self.settings.retention_days is None and self.settings.max_receipts is None:
            return
        payloads = self.read_payloads()
        retained = _apply_retention_rules(payloads, self.settings)
        if len(retained) == len(payloads):
            return
        with self.path.open("w", encoding="utf-8") as handle:
            for payload in retained:
                handle.write(json.dumps(payload, sort_keys=True))
                handle.write("\n")


class _SqliteReceiptBackend(_BaseReceiptBackend):
    name = "sqlite"

    def __init__(self, path: Path, settings: ReceiptSettings) -> None:
        self.path = path
        self.settings = settings
        self._ensure_schema()

    def append(self, receipt: Receipt) -> None:
        payload = receipt.to_payload()
        payload_json = json.dumps(payload, sort_keys=True)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO receipts (
                    created_at,
                    trace_id,
                    action_hash,
                    decision,
                    policy_match,
                    status,
                    approved_by,
                    approved_at,
                    result_preview,
                    error,
                    receipt_hash,
                    payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload["created_at"],
                    payload["trace_id"],
                    payload["action_hash"],
                    payload["decision"],
                    payload["policy_match"],
                    payload["status"],
                    payload["approved_by"],
                    payload["approved_at"],
                    payload["result_preview"],
                    payload["error"],
                    payload["receipt_hash"],
                    payload_json,
                ),
            )
            self._apply_retention(connection)

    def read_payloads(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload_json FROM receipts ORDER BY id ASC"
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def query_payloads(self, query: ReceiptQuery) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []

        where_clauses: list[str] = []
        params: list[Any] = []
        for field_name in ("trace_id", "action_hash", "status", "decision", "policy_match"):
            value = getattr(query, field_name)
            if value is not None:
                where_clauses.append(f"{field_name} = ?")
                params.append(value)

        sql = "SELECT payload_json FROM receipts"
        if where_clauses:
            sql += " WHERE " + " AND ".join(where_clauses)
        sql += f" ORDER BY created_at {'DESC' if query.descending else 'ASC'}, id {'DESC' if query.descending else 'ASC'}"
        if query.limit is not None:
            sql += " LIMIT ?"
            params.append(query.limit)

        with self._connect() as connection:
            rows = connection.execute(sql, params).fetchall()
        return [json.loads(row[0]) for row in rows]

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _ensure_schema(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=NORMAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS receipts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    trace_id TEXT,
                    action_hash TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    policy_match TEXT NOT NULL,
                    status TEXT NOT NULL,
                    approved_by TEXT,
                    approved_at TEXT,
                    result_preview TEXT,
                    error TEXT,
                    receipt_hash TEXT NOT NULL UNIQUE,
                    payload_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_receipts_created_at ON receipts(created_at);
                CREATE INDEX IF NOT EXISTS idx_receipts_trace_id ON receipts(trace_id);
                CREATE INDEX IF NOT EXISTS idx_receipts_action_hash ON receipts(action_hash);
                CREATE INDEX IF NOT EXISTS idx_receipts_status ON receipts(status);
                CREATE INDEX IF NOT EXISTS idx_receipts_decision ON receipts(decision);
                CREATE INDEX IF NOT EXISTS idx_receipts_policy_match ON receipts(policy_match);
                """
            )

    def _apply_retention(self, connection: sqlite3.Connection) -> None:
        if self.settings.retention_days is not None:
            cutoff = _retention_cutoff(self.settings.retention_days)
            connection.execute("DELETE FROM receipts WHERE created_at < ?", (cutoff,))
        if self.settings.max_receipts is not None:
            connection.execute(
                """
                DELETE FROM receipts
                WHERE id NOT IN (
                    SELECT id
                    FROM receipts
                    ORDER BY created_at DESC, id DESC
                    LIMIT ?
                )
                """,
                (max(self.settings.max_receipts, 0),),
            )


def _build_receipt_backend(path: Path, settings: ReceiptSettings) -> _BaseReceiptBackend:
    if path.suffix.lower() in SQLITE_SUFFIXES:
        return _SqliteReceiptBackend(path, settings)
    return _JsonlReceiptBackend(path, settings)


def build_receipt(
    *,
    action: ActionEnvelope,
    authorization: AuthorizationResult,
    status: str,
    result: Any = None,
    error: str | None = None,
    signer: ReceiptSigner | None = None,
    settings: ReceiptSettings | None = None,
) -> Receipt:
    signer = signer or ReceiptSigner()
    settings = settings or ReceiptSettings.from_env()
    receipt_body = {
        "decision": authorization.final_decision,
        "approved_by": authorization.approved_by,
        "approved_at": authorization.approved_at,
        "action_hash": action.fingerprint(),
        "action_summary": _build_action_summary(action, settings),
        "policy_match": authorization.policy_outcome.rule_id,
        "trace_id": action.trace_id,
        "status": status,
        "result_preview": None if result is None else _redact_text(str(result), settings)[:240],
        "error": _redact_text(error, settings),
        "created_at": utc_now(),
    }
    receipt_hash = signer.sign(receipt_body)
    return Receipt(receipt_hash=receipt_hash, **receipt_body)


def verify_receipt_payload(payload: dict[str, Any], signer: ReceiptSigner | None = None) -> bool:
    signer = signer or ReceiptSigner()
    return signer.verify(_unsigned_receipt_payload(payload), payload.get("receipt_hash"))


def sign_bundle_manifest_payload(payload: dict[str, Any], *, signer: ReceiptSigner | None = None) -> str:
    signer = signer or ReceiptSigner()
    return signer.sign(_unsigned_bundle_manifest(payload))


def verify_bundle_manifest_payload(payload: dict[str, Any], signer: ReceiptSigner | None = None) -> bool:
    signer = signer or ReceiptSigner()
    return signer.verify(_unsigned_bundle_manifest(payload), payload.get("manifest_signature"))


def _build_action_summary(action: ActionEnvelope, settings: ReceiptSettings) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "actor": action.actor,
        "surface": action.surface,
        "tool": action.tool,
        "intent": action.intent,
    }
    if action.target:
        summary["target"] = _redact_text(str(action.target), settings)
    if action.session_id:
        summary["session_id"] = _redact_text(str(action.session_id), settings)
    if action.risk:
        summary["risk"] = [str(item) for item in action.risk[:8]]
    metadata_summary = _summarize_mapping(action.metadata, settings)
    if metadata_summary:
        summary["metadata"] = metadata_summary
    return summary


def _unsigned_receipt_payload(payload: dict[str, Any]) -> dict[str, Any]:
    body = dict(payload)
    body.pop("receipt_hash", None)
    return body


def _unsigned_bundle_manifest(payload: dict[str, Any]) -> dict[str, Any]:
    body = dict(payload)
    body.pop("manifest_signature", None)
    return body


def _hash_file(path: Path) -> str:
    return "sha256:" + sha256(path.read_bytes()).hexdigest()


def _redact_text(value: str | None, settings: ReceiptSettings) -> str | None:
    if value is None or not settings.redact_sensitive_values:
        return value
    redacted = value
    for pattern, replacement in SENSITIVE_TEXT_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def _summarize_mapping(
    mapping: dict[str, Any],
    settings: ReceiptSettings,
    *,
    max_items: int = 8,
    max_depth: int = 2,
) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for key, value in list(mapping.items())[:max_items]:
        summary[str(key)] = _summarize_value(value, settings, depth=max_depth)
    return summary


def _summarize_value(value: Any, settings: ReceiptSettings, *, depth: int) -> Any:
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        redacted = _redact_text(value, settings)
        if redacted is None:
            return None
        return redacted if len(redacted) <= 120 else redacted[:117] + "..."
    if depth <= 0:
        redacted = _redact_text(str(value), settings)
        if redacted is None:
            return None
        return redacted if len(redacted) <= 120 else redacted[:117] + "..."
    if isinstance(value, dict):
        return _summarize_mapping(dict(value), settings, max_items=6, max_depth=depth - 1)
    if isinstance(value, (list, tuple)):
        return [
            _summarize_value(item, settings, depth=depth - 1)
            for item in list(value)[:6]
        ]
    redacted = _redact_text(str(value), settings)
    if redacted is None:
        return None
    return redacted if len(redacted) <= 120 else redacted[:117] + "..."


def _payload_matches_query(payload: dict[str, Any], query: ReceiptQuery) -> bool:
    for field_name in ("trace_id", "action_hash", "status", "decision", "policy_match"):
        expected = getattr(query, field_name)
        if expected is not None and str(payload.get(field_name)) != expected:
            return False
    return True


def _build_receipt_traces(
    payloads: list[dict[str, Any]],
    *,
    descending: bool,
) -> list[ReceiptTrace]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    anonymous: list[dict[str, Any]] = []
    for payload in payloads:
        trace_id = payload.get("trace_id")
        if isinstance(trace_id, str) and trace_id:
            grouped.setdefault(trace_id, []).append(payload)
        else:
            anonymous.append(payload)

    traces = [
        _make_receipt_trace(trace_id, receipts)
        for trace_id, receipts in grouped.items()
    ]
    traces.sort(
        key=lambda trace: (
            str(trace.ended_at or trace.started_at or ""),
            trace.trace_id,
        ),
        reverse=descending,
    )

    for index, payload in enumerate(anonymous, start=1):
        traces.append(_make_receipt_trace(f"(no-trace-{index})", [payload]))
    return traces


def _make_receipt_trace(trace_id: str, receipts: list[dict[str, Any]]) -> ReceiptTrace:
    ordered = sorted(
        receipts,
        key=lambda payload: (
            str(payload.get("created_at", "")),
            str(payload.get("receipt_hash", "")),
        ),
    )
    action_hashes = [
        action_hash
        for action_hash in dict.fromkeys(
            str(payload.get("action_hash"))
            for payload in ordered
            if payload.get("action_hash")
        )
    ]
    started_at = str(ordered[0].get("created_at")) if ordered else None
    ended_at = str(ordered[-1].get("created_at")) if ordered else None
    return ReceiptTrace(
        trace_id=trace_id,
        started_at=started_at,
        ended_at=ended_at,
        receipts=ordered,
        action_hashes=action_hashes,
    )


def _apply_retention_rules(
    payloads: list[dict[str, Any]],
    settings: ReceiptSettings,
) -> list[dict[str, Any]]:
    retained = payloads
    if settings.retention_days is not None:
        cutoff = _parse_timestamp(_retention_cutoff(settings.retention_days))
        retained = [
            payload
            for payload in retained
            if (timestamp := _parse_timestamp(str(payload.get("created_at", "")))) is None or timestamp >= cutoff
        ]
    if settings.max_receipts is not None:
        retained = retained[-max(settings.max_receipts, 0) :]
    return retained


def _retention_cutoff(retention_days: int) -> str:
    cutoff = datetime.now(timezone.utc) - timedelta(days=max(retention_days, 0))
    return cutoff.isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _env_flag(name: str, *, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() not in FALSE_VALUES


def _env_int(name: str) -> int | None:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return None
    value = int(raw)
    return value if value >= 0 else None


def add_receipt_settings_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--receipt-redaction",
        choices=["on", "off"],
        default=None,
        help="Override receipt preview redaction behavior (default: env or on)",
    )
    parser.add_argument(
        "--receipt-retention-days",
        type=_nonnegative_int,
        default=None,
        help="Keep only the last N days of receipts",
    )
    parser.add_argument(
        "--receipt-max-receipts",
        type=_nonnegative_int,
        default=None,
        help="Keep only the newest N receipts",
    )


def receipt_settings_from_args(args: Any) -> ReceiptSettings:
    settings = ReceiptSettings.from_env()
    redaction = getattr(args, "receipt_redaction", None)
    if redaction is not None:
        settings.redact_sensitive_values = redaction == "on"
    retention_days = getattr(args, "receipt_retention_days", None)
    if retention_days is not None:
        settings.retention_days = retention_days
    max_receipts = getattr(args, "receipt_max_receipts", None)
    if max_receipts is not None:
        settings.max_receipts = max_receipts
    return settings


def build_query_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Query DualKey receipt stores")
    parser.add_argument("path", help="Path to a DualKey receipt store (.jsonl, .sqlite, .sqlite3, or .db)")
    parser.add_argument("--trace-id", default=None, help="Filter by trace_id")
    parser.add_argument("--action-hash", default=None, help="Filter by action_hash")
    parser.add_argument("--status", default=None, help="Filter by receipt status")
    parser.add_argument("--decision", default=None, help="Filter by decision")
    parser.add_argument("--policy-match", default=None, help="Filter by policy rule id")
    parser.add_argument("--limit", type=_nonnegative_int, default=None, help="Return at most N receipts")
    parser.add_argument(
        "--order",
        choices=["asc", "desc"],
        default="asc",
        help="Sort by created_at",
    )
    parser.add_argument(
        "--format",
        choices=["table", "json", "jsonl", "timeline", "markdown", "bundle"],
        default="table",
        help="How to print query results",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Write the rendered output to a file, or a bundle directory when --format bundle",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_query_parser()
    args = parser.parse_args(argv)

    store = ReceiptStore(Path(args.path))
    query = ReceiptQuery(
        trace_id=args.trace_id,
        action_hash=args.action_hash,
        status=args.status,
        decision=args.decision,
        policy_match=args.policy_match,
        limit=args.limit,
        descending=args.order == "desc",
    )
    if args.format == "bundle":
        if not args.output:
            parser.error("--output is required when --format bundle")
        store.export_bundle(args.output, query)
        return 0
    payloads = store.query_payloads(query)
    output = _render_query_results(payloads, output_format=args.format, descending=query.descending)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output, encoding="utf-8")
    elif output:
        print(output)
    return 0


def _render_query_results(payloads: list[dict[str, Any]], *, output_format: str, descending: bool) -> str:
    if output_format == "json":
        return json.dumps(payloads, ensure_ascii=True, indent=2)
    if output_format == "jsonl":
        return "\n".join(
            json.dumps(payload, ensure_ascii=True, separators=(",", ":"))
            for payload in payloads
        )
    if output_format == "timeline":
        return _render_receipt_timeline(_build_receipt_traces(payloads, descending=descending))
    if output_format == "markdown":
        return _render_receipt_markdown_report(_build_receipt_traces(payloads, descending=descending), descending=descending)
    return _render_receipt_table(payloads)


def _render_receipt_table(payloads: list[dict[str, Any]]) -> str:
    columns = [
        ("created_at", "created_at"),
        ("decision", "decision"),
        ("status", "status"),
        ("policy_match", "policy_match"),
        ("trace_id", "trace_id"),
    ]
    if not payloads:
        return "(no receipts matched)"

    widths = {
        label: max(len(label), *(len(_table_cell(payload.get(key))) for payload in payloads))
        for key, label in columns
    }
    lines = [
        "  ".join(label.ljust(widths[label]) for _, label in columns),
        "  ".join("-" * widths[label] for _, label in columns),
    ]
    for payload in payloads:
        lines.append(
            "  ".join(
                _table_cell(payload.get(key)).ljust(widths[label])
                for key, label in columns
            )
        )
    return "\n".join(lines)


def _table_cell(value: Any) -> str:
    if value is None:
        return "-"
    text = str(value)
    return text if len(text) <= 48 else text[:45] + "..."


def _render_receipt_timeline(traces: list[ReceiptTrace]) -> str:
    if not traces:
        return "(no receipts matched)"
    blocks: list[str] = []
    for index, trace in enumerate(traces):
        if index:
            blocks.append("")
        blocks.append(_render_single_trace(trace))
    return "\n".join(blocks)


def _render_single_trace(trace: ReceiptTrace) -> str:
    lines = [
        f"trace_id: {trace.trace_id}",
        f"started_at: {trace.started_at or '-'}",
        f"ended_at: {trace.ended_at or '-'}",
    ]
    if trace.action_hashes:
        lines.append(f"action_hashes: {', '.join(trace.action_hashes)}")
    for position, payload in enumerate(trace.receipts, start=1):
        line = (
            f"{position}. {payload.get('created_at', '-')} "
            f"{payload.get('status', '-')} "
            f"{payload.get('decision', '-')}"
        )
        if payload.get("policy_match"):
            line += f" policy={payload['policy_match']}"
        lines.append(line)
        if payload.get("approved_by"):
            lines.append(f"   approved_by: {payload['approved_by']}")
        if payload.get("error"):
            lines.append(f"   error: {payload['error']}")
        elif payload.get("result_preview"):
            lines.append(f"   result: {payload['result_preview']}")
    return "\n".join(lines)


def _render_receipt_markdown_report(traces: list[ReceiptTrace], *, descending: bool) -> str:
    if not traces:
        return "# DualKey Audit Report\n\n_No receipts matched._"

    total_receipts = sum(len(trace.receipts) for trace in traces)
    latest_timestamp = next(
        (
            trace.ended_at or trace.started_at
            for trace in traces
            if trace.ended_at or trace.started_at
        ),
        None,
    )
    lines = [
        "# DualKey Audit Report",
        "",
        "## Summary",
        "",
        f"- traces: {len(traces)}",
        f"- receipts: {total_receipts}",
        f"- order: {'descending' if descending else 'ascending'}",
    ]
    if latest_timestamp:
        lines.append(f"- latest_event_at: {latest_timestamp}")

    lines.extend([
        "",
        "## Status Breakdown",
        "",
        *_render_count_lines(_count_trace_field(traces, "status")),
        "",
        "## Decision Breakdown",
        "",
        *_render_count_lines(_count_trace_field(traces, "decision")),
        "",
        "## Policy Breakdown",
        "",
        *_render_count_lines(_count_trace_field(traces, "policy_match")),
    ])

    for trace in traces:
        lines.extend([
            "",
            f"## Trace `{trace.trace_id}`",
            "",
            f"- started_at: {trace.started_at or '-'}",
            f"- ended_at: {trace.ended_at or '-'}",
            f"- steps: {len(trace.receipts)}",
        ])
        if trace.action_hashes:
            lines.append(f"- action_hashes: {', '.join(trace.action_hashes)}")
        lines.extend([
            "",
            "| # | created_at | status | decision | policy | approved_by | approved_at |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ])
        for index, payload in enumerate(trace.receipts, start=1):
            lines.append(
                "| "
                + " | ".join(
                    [
                        str(index),
                        _markdown_cell(payload.get("created_at")),
                        _markdown_cell(payload.get("status")),
                        _markdown_cell(payload.get("decision")),
                        _markdown_cell(payload.get("policy_match")),
                        _markdown_cell(payload.get("approved_by")),
                        _markdown_cell(payload.get("approved_at")),
                    ]
                )
                + " |"
            )
            details = _receipt_detail_lines(payload)
            if details:
                lines.extend(["", "Details:"])
                lines.extend([f"- {detail}" for detail in details])
                lines.append("")
        if lines[-1] != "":
            lines.append("")
    return "\n".join(lines).rstrip()


def _count_trace_field(traces: list[ReceiptTrace], field_name: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for trace in traces:
        for payload in trace.receipts:
            key = str(payload.get(field_name) or "(none)")
            counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def _render_count_lines(counts: dict[str, int]) -> list[str]:
    if not counts:
        return ["- (none)"]
    return [f"- {key}: {value}" for key, value in counts.items()]


def _build_bundle_manifest(
    *,
    backend_name: str,
    query: ReceiptQuery,
    traces: list[ReceiptTrace],
    payloads: list[dict[str, Any]],
    files: dict[str, str],
    file_hashes: dict[str, str],
) -> dict[str, Any]:
    action_hashes = list(
        dict.fromkeys(
            str(payload.get("action_hash"))
            for payload in payloads
            if payload.get("action_hash")
        )
    )
    return {
        "format_version": "dualkey.bundle.v1",
        "generated_at": utc_now(),
        "backend": backend_name,
        "query": {
            "trace_id": query.trace_id,
            "action_hash": query.action_hash,
            "status": query.status,
            "decision": query.decision,
            "policy_match": query.policy_match,
            "limit": query.limit,
            "descending": query.descending,
        },
        "trace_count": len(traces),
        "receipt_count": len(payloads),
        "trace_ids": [trace.trace_id for trace in traces],
        "action_hashes": action_hashes,
        "action_context": {
            "actors": _unique_action_summary_values(payloads, "actor"),
            "surfaces": _unique_action_summary_values(payloads, "surface"),
            "tools": _unique_action_summary_values(payloads, "tool"),
        },
        "files": files,
        "file_hashes": file_hashes,
    }


def _receipt_detail_lines(payload: dict[str, Any]) -> list[str]:
    details: list[str] = []
    action_summary = payload.get("action_summary")
    if isinstance(action_summary, dict):
        overlay = _format_action_summary_inline(action_summary)
        if overlay:
            details.append(f"context: `{overlay}`")
    action_hash = payload.get("action_hash")
    if action_hash:
        details.append(f"action_hash: `{action_hash}`")
    result_preview = payload.get("result_preview")
    if result_preview:
        details.append(f"result: `{_markdown_inline(result_preview)}`")
    error = payload.get("error")
    if error:
        details.append(f"error: `{_markdown_inline(error)}`")
    return details


def _markdown_cell(value: Any) -> str:
    if value is None or value == "":
        return "-"
    return str(value).replace("|", "\\|")


def _markdown_inline(value: Any) -> str:
    return str(value).replace("`", "\\`")


def _unique_action_summary_values(payloads: list[dict[str, Any]], key: str) -> list[str]:
    values = dict.fromkeys(
        str(summary.get(key))
        for payload in payloads
        if isinstance(summary := payload.get("action_summary"), dict) and summary.get(key)
    )
    return list(values)


def _format_action_summary_inline(action_summary: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("actor", "surface", "tool", "intent", "target"):
        value = action_summary.get(key)
        if value:
            parts.append(f"{key}={value}")
    risk_values = action_summary.get("risk")
    if isinstance(risk_values, list) and risk_values:
        parts.append("risk=" + ",".join(str(item) for item in risk_values))
    return " ".join(parts).replace("`", "\\`")

def _nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be >= 0")
    return parsed


if __name__ == "__main__":
    raise SystemExit(main())
