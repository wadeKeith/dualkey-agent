from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from dualkey.approvals import ApprovalHandler, ConsoleApprover
from dualkey.models import ActionEnvelope, AuthorizationResult
from dualkey.policy import Policy, load_policy
from dualkey.receipts import ReceiptSettings, ReceiptSigner, ReceiptStore, build_receipt


def _normalize_action(action: ActionEnvelope | Mapping[str, Any]) -> ActionEnvelope:
    if isinstance(action, ActionEnvelope):
        return action
    return ActionEnvelope.from_mapping(action)


class DualKey:
    def __init__(
        self,
        policy: Policy,
        *,
        approver: ApprovalHandler | None = None,
        receipt_store: ReceiptStore | None = None,
        receipt_settings: ReceiptSettings | None = None,
        signer: ReceiptSigner | None = None,
    ) -> None:
        self.policy = policy
        self.approver = approver or ConsoleApprover(auto_approve=False)
        self.receipt_settings = receipt_settings or getattr(receipt_store, "settings", None) or ReceiptSettings.from_env()
        self.receipt_store = receipt_store or ReceiptStore(settings=self.receipt_settings)
        if receipt_store is not None and hasattr(self.receipt_store, "settings"):
            self.receipt_store.settings = self.receipt_settings
        self.signer = signer or ReceiptSigner()

    @classmethod
    def from_file(
        cls,
        policy_path: str | Path,
        *,
        approver: ApprovalHandler | None = None,
        receipts_path: str | Path = ".dualkey/receipts.jsonl",
        receipt_settings: ReceiptSettings | None = None,
        signer: ReceiptSigner | None = None,
    ) -> "DualKey":
        return cls(
            load_policy(policy_path),
            approver=approver,
            receipt_store=ReceiptStore(receipts_path, settings=receipt_settings),
            receipt_settings=receipt_settings,
            signer=signer,
        )

    def authorize(self, action: ActionEnvelope | Mapping[str, Any]) -> AuthorizationResult:
        envelope = _normalize_action(action)
        outcome = self.policy.evaluate(envelope)

        if outcome.decision == "allow":
            return AuthorizationResult(
                allowed=True,
                final_decision="allow",
                policy_outcome=outcome,
            )

        if outcome.decision == "deny":
            return AuthorizationResult(
                allowed=False,
                final_decision="deny",
                policy_outcome=outcome,
            )

        approval = self.approver.review(envelope, outcome)
        final_decision = "ask->approved" if approval.approved else "ask->rejected"
        return AuthorizationResult(
            allowed=approval.approved,
            final_decision=final_decision,
            policy_outcome=outcome,
            approved_by=approval.approver,
            approval_note=approval.note,
            approved_at=approval.approved_at,
        )

    def run_action(self, action: ActionEnvelope | Mapping[str, Any], executor: Any | None = None) -> Any:
        envelope = _normalize_action(action)
        authorization = self.authorize(envelope)
        if not authorization.allowed:
            receipt = build_receipt(
                action=envelope,
                authorization=authorization,
                status="blocked",
                error=f"blocked by {authorization.policy_outcome.rule_id}",
                signer=self.signer,
                settings=self.receipt_settings,
            )
            self.receipt_store.append(receipt)
            raise PermissionError(
                f"{authorization.final_decision}: {authorization.policy_outcome.reason}"
            )

        if executor is None:
            receipt = build_receipt(
                action=envelope,
                authorization=authorization,
                status="authorized",
                signer=self.signer,
                settings=self.receipt_settings,
            )
            self.receipt_store.append(receipt)
            return authorization

        try:
            result = executor(envelope)
        except Exception as exc:
            receipt = build_receipt(
                action=envelope,
                authorization=authorization,
                status="error",
                error=str(exc),
                signer=self.signer,
                settings=self.receipt_settings,
            )
            self.receipt_store.append(receipt)
            raise

        receipt = build_receipt(
            action=envelope,
            authorization=authorization,
            status="executed",
            result=result,
            signer=self.signer,
            settings=self.receipt_settings,
        )
        self.receipt_store.append(receipt)
        return result


class ProtectedAgent:
    def __init__(self, agent: Any, gate: DualKey) -> None:
        self._agent = agent
        self._gate = gate

    def __getattr__(self, item: str) -> Any:
        return getattr(self._agent, item)

    def run(self, task: str) -> list[dict[str, Any]]:
        if not hasattr(self._agent, "plan"):
            raise TypeError("Protected agent requires an underlying agent.plan(task) method")
        if not hasattr(self._agent, "execute_action"):
            raise TypeError(
                "Protected agent requires an underlying agent.execute_action(action) method"
            )

        report: list[dict[str, Any]] = []
        for action in self._agent.plan(task):
            envelope = _normalize_action(action)
            try:
                result = self._gate.run_action(envelope, self._agent.execute_action)
                report.append(
                    {
                        "tool": envelope.tool,
                        "target": envelope.target,
                        "status": "executed",
                        "result": result,
                    }
                )
            except PermissionError as exc:
                report.append(
                    {
                        "tool": envelope.tool,
                        "target": envelope.target,
                        "status": "blocked",
                        "error": str(exc),
                    }
                )
        return report


def protect(
    agent: Any,
    *,
    policy: str | Path | Policy,
    approver: ApprovalHandler | None = None,
    receipts_path: str | Path = ".dualkey/receipts.jsonl",
    receipt_settings: ReceiptSettings | None = None,
    signer: ReceiptSigner | None = None,
) -> ProtectedAgent:
    gate = DualKey(
        load_policy(policy),
        approver=approver,
        receipt_store=ReceiptStore(receipts_path, settings=receipt_settings),
        receipt_settings=receipt_settings,
        signer=signer,
    )
    return ProtectedAgent(agent, gate)
