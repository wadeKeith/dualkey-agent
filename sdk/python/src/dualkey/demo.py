from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from dualkey.approvals import ConsoleApprover
from dualkey.engine import protect
from dualkey.models import ActionEnvelope
from dualkey.receipts import ReceiptSettings, add_receipt_settings_arguments, receipt_settings_from_args


def repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def default_policy_path() -> Path:
    return repo_root() / "policy" / "examples" / "dualkey.yaml"


class ToyCodingAgent:
    def plan(self, task: str) -> list[ActionEnvelope]:
        return [
            ActionEnvelope(
                actor="openhands",
                surface="shell",
                tool="filesystem.write",
                intent="write",
                target="/repo/.env",
                args={"path": "/repo/.env", "content_preview": "OPENAI_API_KEY=***"},
                risk=["secrets", "write", "critical-file"],
                session_id="sess_gitpush",
                trace_id="trace_gitpush_write",
            ),
            ActionEnvelope(
                actor="openhands",
                surface="shell",
                tool="shell.exec",
                intent="execute",
                target="origin/main",
                args={"command": "git push origin main"},
                risk=["git", "branch-protection"],
                session_id="sess_gitpush",
                trace_id="trace_gitpush_push",
            ),
        ]

    def execute_action(self, action: ActionEnvelope) -> str:
        if action.tool == "shell.exec":
            return f"executed command: {action.args['command']}"
        if action.tool == "filesystem.write":
            return f"wrote file: {action.target}"
        return f"completed: {action.tool}"


class ToyBrowserAgent:
    def plan(self, task: str) -> list[ActionEnvelope]:
        return [
            ActionEnvelope(
                actor="browser-use",
                surface="browser",
                tool="browser.click",
                intent="click",
                target="button#pay-now",
                args={
                    "selector": "button#pay-now",
                    "amount": "149.00",
                    "shipping_address": "1 Demo Way, Shanghai",
                },
                risk=["payment", "checkout"],
                session_id="sess_payment",
                trace_id="trace_payment_click",
            )
        ]

    def execute_action(self, action: ActionEnvelope) -> str:
        return f"clicked {action.target}"


class ToyShellAgent:
    def plan(self, task: str) -> list[ActionEnvelope]:
        return [
            ActionEnvelope(
                actor="claude-code",
                surface="shell",
                tool="shell.exec",
                intent="execute",
                target="/tmp/demo",
                args={"command": "rm -rf /tmp/demo"},
                risk=["destructive", "filesystem"],
                session_id="sess_shell",
                trace_id="trace_shell_deny",
            )
        ]

    def execute_action(self, action: ActionEnvelope) -> str:
        return f"executed command: {action.args['command']}"


def run_named_scenario(
    name: str,
    *,
    policy_path: str | Path | None = None,
    auto_approve: bool = False,
    receipts_path: str | Path = ".dualkey/receipts.jsonl",
    receipt_settings: ReceiptSettings | None = None,
) -> list[dict[str, Any]]:
    policy_path = Path(policy_path or default_policy_path())
    approver = ConsoleApprover(auto_approve=auto_approve)

    agents = {
        "git-push": ToyCodingAgent(),
        "payment": ToyBrowserAgent(),
        "dangerous-shell": ToyShellAgent(),
    }
    tasks = {
        "git-push": "fix the bug and open a PR",
        "payment": "finish checkout",
        "dangerous-shell": "clean up temp files",
    }
    if name not in agents:
        raise ValueError(f"Unknown scenario: {name}")

    protected = protect(
        agents[name],
        policy=policy_path,
        approver=approver,
        receipts_path=receipts_path,
        receipt_settings=receipt_settings,
    )
    return protected.run(tasks[name])


def print_report(name: str, report: list[dict[str, Any]]) -> None:
    print(f"\n=== scenario: {name} ===")
    for item in report:
        if item["status"] == "executed":
            print(f"[executed] {item['tool']} -> {item['result']}")
        else:
            print(f"[blocked] {item['tool']} -> {item['error']}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run DualKey demo scenarios")
    parser.add_argument(
        "scenario",
        choices=["git-push", "payment", "dangerous-shell", "all"],
        help="Which scenario to run",
    )
    parser.add_argument(
        "--policy",
        default=str(default_policy_path()),
        help="Path to the DualKey policy file",
    )
    parser.add_argument(
        "--receipts",
        default=".dualkey/receipts.jsonl",
        help="Where to append receipts (.jsonl, .sqlite, .sqlite3, or .db)",
    )
    parser.add_argument(
        "--auto-approve",
        action="store_true",
        help="Auto-approve actions that resolve to ask",
    )
    add_receipt_settings_arguments(parser)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    scenarios = ["git-push", "payment", "dangerous-shell"] if args.scenario == "all" else [args.scenario]
    receipt_settings = receipt_settings_from_args(args)
    for scenario in scenarios:
        report = run_named_scenario(
            scenario,
            policy_path=args.policy,
            auto_approve=args.auto_approve,
            receipts_path=args.receipts,
            receipt_settings=receipt_settings,
        )
        print_report(scenario, report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
