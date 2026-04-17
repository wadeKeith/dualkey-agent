from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
import json
from typing import Any, Literal, Mapping

Decision = Literal["allow", "ask", "deny"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(slots=True)
class ActionEnvelope:
    actor: str
    surface: str
    tool: str
    intent: str
    target: str | None = None
    args: dict[str, Any] = field(default_factory=dict)
    risk: list[str] = field(default_factory=list)
    session_id: str | None = None
    trace_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utc_now)

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "ActionEnvelope":
        return cls(
            actor=str(payload["actor"]),
            surface=str(payload["surface"]),
            tool=str(payload["tool"]),
            intent=str(payload["intent"]),
            target=payload.get("target"),
            args=dict(payload.get("args", {})),
            risk=list(payload.get("risk", [])),
            session_id=payload.get("session_id"),
            trace_id=payload.get("trace_id"),
            metadata=dict(payload.get("metadata", {})),
            created_at=str(payload.get("created_at", utc_now())),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "actor": self.actor,
            "surface": self.surface,
            "tool": self.tool,
            "intent": self.intent,
            "target": self.target,
            "args": self.args,
            "risk": self.risk,
            "session_id": self.session_id,
            "trace_id": self.trace_id,
            "metadata": self.metadata,
            "created_at": self.created_at,
        }

    def fingerprint(self) -> str:
        body = json.dumps(self.to_payload(), sort_keys=True, separators=(",", ":"))
        return f"sha256:{sha256(body.encode('utf-8')).hexdigest()}"

    def preview(self) -> list[str]:
        lines = [
            f"actor: {self.actor}",
            f"surface: {self.surface}",
            f"tool: {self.tool}",
            f"intent: {self.intent}",
        ]
        if self.target:
            lines.append(f"target: {self.target}")
        if self.args:
            lines.append(f"args: {json.dumps(self.args, sort_keys=True)}")
        if self.risk:
            lines.append(f"risk: {', '.join(self.risk)}")
        if self.trace_id:
            lines.append(f"trace_id: {self.trace_id}")
        return lines


@dataclass(slots=True)
class PolicyOutcome:
    decision: Decision
    rule_id: str
    reason: str


@dataclass(slots=True)
class ApprovalDecision:
    approved: bool
    approver: str
    note: str | None = None
    approved_at: str = field(default_factory=utc_now)


@dataclass(slots=True)
class AuthorizationResult:
    allowed: bool
    final_decision: str
    policy_outcome: PolicyOutcome
    approved_by: str | None = None
    approval_note: str | None = None
    approved_at: str | None = None


@dataclass(slots=True)
class Receipt:
    decision: str
    approved_by: str | None
    approved_at: str | None
    action_hash: str
    policy_match: str
    trace_id: str | None
    status: str
    result_preview: str | None
    error: str | None
    created_at: str
    receipt_hash: str
    action_summary: dict[str, Any] | None = None

    def to_payload(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
            "action_hash": self.action_hash,
            "action_summary": self.action_summary,
            "policy_match": self.policy_match,
            "trace_id": self.trace_id,
            "status": self.status,
            "result_preview": self.result_preview,
            "error": self.error,
            "created_at": self.created_at,
            "receipt_hash": self.receipt_hash,
        }
