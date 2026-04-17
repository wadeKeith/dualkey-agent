from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Mapping

from dualkey.models import ActionEnvelope, AuthorizationResult
from dualkey.policy import Policy, load_policy
from dualkey.receipts import (
    ReceiptSettings,
    ReceiptSigner,
    ReceiptStore,
    add_receipt_settings_arguments,
    build_receipt,
    receipt_settings_from_args,
)


READ_TOOLS = {"Read", "Grep", "Glob", "LS"}
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
NETWORK_TOOLS = {"WebFetch", "WebSearch"}
HUMAN_LOOP_TOOLS = {"AskUserQuestion", "ExitPlanMode"}
TARGET_KEYS = (
    "file_path",
    "notebook_path",
    "path",
    "url",
    "command",
    "query",
    "pattern",
)
SECRET_MARKERS = (".env", "/.ssh/", "id_rsa", "secret", "token", "api_key")
PAYMENT_MARKERS = ("pay", "checkout", "purchase", "payment")
PROD_MARKERS = ("kubectl apply", "terraform apply", "prod", "production")


class ClaudeCodeHookAdapter:
    def __init__(
        self,
        *,
        policy: Policy,
        receipt_store: ReceiptStore | None = None,
        receipt_settings: ReceiptSettings | None = None,
        signer: ReceiptSigner | None = None,
        echo_first_suggestion: bool = False,
    ) -> None:
        self.policy = policy
        self.receipt_settings = receipt_settings or getattr(receipt_store, "settings", None) or ReceiptSettings.from_env()
        self.receipt_store = receipt_store or ReceiptStore(
            ".dualkey/claude-code-receipts.jsonl",
            settings=self.receipt_settings,
        )
        if receipt_store is not None and hasattr(self.receipt_store, "settings"):
            self.receipt_store.settings = self.receipt_settings
        self.signer = signer or ReceiptSigner()
        self.echo_first_suggestion = echo_first_suggestion

    def handle(self, payload: Mapping[str, Any]) -> dict[str, Any] | None:
        event_name = str(payload.get("hook_event_name", ""))
        if event_name not in {
            "PreToolUse",
            "PermissionRequest",
            "PostToolUse",
            "PostToolUseFailure",
            "PermissionDenied",
        }:
            return None

        action = self._build_action_envelope(payload)
        outcome = self.policy.evaluate(action)

        if event_name == "PreToolUse":
            authorization = self._authorization_from_outcome(outcome, approved_by="dualkey:policy")
            self._append_receipt(
                action=action,
                authorization=authorization,
                status="claude_pre_tool_use",
                result={"event": event_name},
            )
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": outcome.decision,
                    "permissionDecisionReason": (
                        f"DualKey {outcome.decision} via rule '{outcome.rule_id}'."
                    ),
                }
            }

        if event_name == "PermissionRequest":
            authorization = self._authorization_from_outcome(outcome, approved_by="dualkey:policy")
            self._append_receipt(
                action=action,
                authorization=authorization,
                status="claude_permission_request",
                result={"event": event_name},
            )
            if outcome.decision == "allow":
                decision: dict[str, Any] = {"behavior": "allow"}
                suggestions = payload.get("permission_suggestions", [])
                if self.echo_first_suggestion and isinstance(suggestions, list) and suggestions:
                    decision["updatedPermissions"] = [suggestions[0]]
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PermissionRequest",
                        "decision": decision,
                    }
                }
            if outcome.decision == "deny":
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PermissionRequest",
                        "decision": {
                            "behavior": "deny",
                            "message": f"DualKey denied this request via rule '{outcome.rule_id}'.",
                            "interrupt": False,
                        },
                    }
                }
            return None

        if event_name == "PostToolUse":
            authorization = self._authorization_from_outcome(outcome, approved_by="claude-code")
            self._append_receipt(
                action=action,
                authorization=authorization,
                status="executed",
                result=payload.get("tool_response"),
            )
            return None

        if event_name == "PostToolUseFailure":
            authorization = self._authorization_from_outcome(outcome, approved_by="claude-code")
            self._append_receipt(
                action=action,
                authorization=authorization,
                status="error",
                error=str(payload.get("error", "unknown tool failure")),
            )
            return None

        authorization = AuthorizationResult(
            allowed=False,
            final_decision="deny",
            policy_outcome=outcome,
            approved_by="claude-code:auto-mode",
        )
        self._append_receipt(
            action=action,
            authorization=authorization,
            status="permission_denied",
            error=str(payload.get("reason", "permission denied")),
        )
        return None

    def _build_action_envelope(self, payload: Mapping[str, Any]) -> ActionEnvelope:
        event_name = str(payload.get("hook_event_name", ""))
        tool_name = str(payload.get("tool_name", "unknown"))
        raw_input = payload.get("tool_input", {})
        tool_input = dict(raw_input) if isinstance(raw_input, Mapping) else {}
        target = self._extract_target(tool_input)
        risk = self._derive_risk(tool_name=tool_name, tool_input=tool_input, target=target)
        metadata = {
            "hook_event_name": event_name,
            "cwd": payload.get("cwd"),
            "permission_mode": payload.get("permission_mode"),
            "tool_use_id": payload.get("tool_use_id"),
            "transcript_path": payload.get("transcript_path"),
            "agent_id": payload.get("agent_id"),
            "agent_type": payload.get("agent_type"),
            "permission_suggestions": payload.get("permission_suggestions"),
            "reason": payload.get("reason"),
        }
        return ActionEnvelope(
            actor="claude-code",
            surface="claude-code",
            tool=tool_name,
            intent=self._derive_intent(tool_name, tool_input),
            target=target,
            args=self._sanitize_value(tool_input),
            risk=sorted(risk),
            session_id=str(payload.get("session_id") or "claude-session"),
            trace_id=self._build_trace_id(payload),
            metadata={key: value for key, value in metadata.items() if value is not None},
        )

    def _build_trace_id(self, payload: Mapping[str, Any]) -> str:
        parts = [
            str(payload.get("session_id") or "claude-session"),
            str(payload.get("hook_event_name") or "unknown"),
            str(payload.get("tool_use_id") or payload.get("tool_name") or "tool"),
        ]
        return ":".join(parts)

    def _derive_intent(self, tool_name: str, tool_input: Mapping[str, Any]) -> str:
        if tool_name in READ_TOOLS:
            return "read"
        if tool_name in WRITE_TOOLS:
            return "write"
        if tool_name == "Bash":
            return "execute"
        if tool_name in NETWORK_TOOLS:
            return "read"
        if tool_name in HUMAN_LOOP_TOOLS:
            return "prompt"
        if tool_name == "Agent":
            return "delegate"
        if tool_name.startswith("mcp__"):
            return "invoke"
        if "command" in tool_input:
            return "execute"
        return "invoke"

    def _derive_risk(
        self,
        *,
        tool_name: str,
        tool_input: Mapping[str, Any],
        target: str | None,
    ) -> set[str]:
        risk: set[str] = set()
        if tool_name in READ_TOOLS:
            risk.add("read-only")
        if tool_name in WRITE_TOOLS:
            risk.add("write")
        if tool_name == "Bash":
            risk.add("shell")
        if tool_name in NETWORK_TOOLS:
            risk.update({"network", "open-world"})
        if tool_name in HUMAN_LOOP_TOOLS:
            risk.add("human-loop")
        if tool_name == "Agent":
            risk.add("multi-agent")
        if tool_name.startswith("mcp__"):
            risk.add("mcp")

        for key, value in self._iter_strings(tool_input):
            lowered_key = key.lower()
            lowered_value = value.lower()
            if any(marker in lowered_key for marker in ("token", "secret", "password", "authorization", "api_key")):
                risk.add("secrets")
            if any(marker in lowered_value for marker in SECRET_MARKERS):
                risk.update({"secrets", "critical-file"})
            if "git push" in lowered_value:
                risk.update({"git", "network"})
            if "rm -rf" in lowered_value:
                risk.add("destructive")
            if any(marker in lowered_value for marker in PAYMENT_MARKERS):
                risk.add("payment")
            if any(marker in lowered_value for marker in PROD_MARKERS):
                risk.add("prod")
            if lowered_value.startswith("http://") or lowered_value.startswith("https://"):
                risk.add("network")

        if target:
            lowered_target = target.lower()
            if any(marker in lowered_target for marker in SECRET_MARKERS):
                risk.update({"secrets", "critical-file"})
            if any(marker in lowered_target for marker in PAYMENT_MARKERS):
                risk.add("payment")

        return risk

    def _extract_target(self, tool_input: Mapping[str, Any]) -> str | None:
        for key in TARGET_KEYS:
            value = tool_input.get(key)
            if isinstance(value, str) and value:
                return value
        return None

    def _iter_strings(self, value: Any, prefix: str = "") -> list[tuple[str, str]]:
        if isinstance(value, Mapping):
            output: list[tuple[str, str]] = []
            for key, item in value.items():
                next_prefix = f"{prefix}.{key}" if prefix else str(key)
                output.extend(self._iter_strings(item, next_prefix))
            return output
        if isinstance(value, list):
            output: list[tuple[str, str]] = []
            for index, item in enumerate(value):
                next_prefix = f"{prefix}.{index}" if prefix else str(index)
                output.extend(self._iter_strings(item, next_prefix))
            return output
        if isinstance(value, str):
            return [(prefix, value)]
        return []

    def _sanitize_value(self, value: Any, key: str | None = None) -> Any:
        if isinstance(value, Mapping):
            return {
                item_key: self._sanitize_value(item_value, key=item_key)
                for item_key, item_value in value.items()
            }
        if isinstance(value, list):
            return [self._sanitize_value(item) for item in value]
        if isinstance(value, str):
            if key and any(marker in key.lower() for marker in ("token", "secret", "password", "authorization", "api_key")):
                return "***"
            if len(value) > 500:
                return value[:497] + "..."
        return value

    def _authorization_from_outcome(self, outcome: Any, approved_by: str | None = None) -> AuthorizationResult:
        return AuthorizationResult(
            allowed=outcome.decision == "allow",
            final_decision=outcome.decision,
            policy_outcome=outcome,
            approved_by=approved_by,
        )

    def _append_receipt(
        self,
        *,
        action: ActionEnvelope,
        authorization: AuthorizationResult,
        status: str,
        result: Any = None,
        error: str | None = None,
    ) -> None:
        receipt = build_receipt(
            action=action,
            authorization=authorization,
            status=status,
            result=result,
            error=error,
            signer=self.signer,
            settings=self.receipt_settings,
        )
        self.receipt_store.append(receipt)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DualKey Claude Code hook adapter")
    parser.add_argument("--policy", required=True, help="Path to the DualKey YAML policy")
    parser.add_argument(
        "--receipts",
        default=".dualkey/claude-code-receipts.jsonl",
        help="Path to append receipts (.jsonl, .sqlite, .sqlite3, or .db)",
    )
    parser.add_argument(
        "--echo-first-suggestion",
        action="store_true",
        help="When allowing a PermissionRequest, echo the first permission suggestion back as updatedPermissions",
    )
    add_receipt_settings_arguments(parser)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        print(f"dualkey-claude-hook: invalid JSON on stdin: {exc}", file=sys.stderr)
        return 1

    receipt_settings = receipt_settings_from_args(args)
    adapter = ClaudeCodeHookAdapter(
        policy=load_policy(Path(args.policy)),
        receipt_store=ReceiptStore(args.receipts, settings=receipt_settings),
        receipt_settings=receipt_settings,
        echo_first_suggestion=args.echo_first_suggestion,
    )
    output = adapter.handle(payload)
    if output is not None:
        print(json.dumps(output, ensure_ascii=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
