from __future__ import annotations

from typing import Protocol, TextIO
import sys

from dualkey.models import ActionEnvelope, ApprovalDecision, PolicyOutcome


class ApprovalHandler(Protocol):
    def review(self, action: ActionEnvelope, outcome: PolicyOutcome) -> ApprovalDecision:
        ...


class ConsoleApprover:
    def __init__(
        self,
        *,
        auto_approve: bool = False,
        identity: str = "human:console",
        stdin: TextIO | None = None,
        stdout: TextIO | None = None,
    ) -> None:
        self.auto_approve = auto_approve
        self.identity = identity
        self.stdin = stdin or sys.stdin
        self.stdout = stdout or sys.stdout

    def review(self, action: ActionEnvelope, outcome: PolicyOutcome) -> ApprovalDecision:
        if self.auto_approve:
            return ApprovalDecision(
                approved=True,
                approver=self.identity,
                note="auto-approved by console approver",
            )

        self.stdout.write("\n=== DualKey Approval Request ===\n")
        for line in action.preview():
            self.stdout.write(f"{line}\n")
        self.stdout.write(f"policy_match: {outcome.rule_id}\n")
        self.stdout.write("approve? [y/N]: ")
        self.stdout.flush()

        if not hasattr(self.stdin, "isatty") or not self.stdin.isatty():
            return ApprovalDecision(
                approved=False,
                approver=self.identity,
                note="denied because no interactive second key was available",
            )

        answer = self.stdin.readline().strip().lower()
        approved = answer in {"y", "yes"}
        return ApprovalDecision(
            approved=approved,
            approver=self.identity,
            note="approved by human" if approved else "rejected by human",
        )
