from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
from pathlib import Path
import sys
from typing import Any

import yaml

from dualkey.policy import PolicyExplanation, load_policy


@dataclass(slots=True)
class PolicyTestCaseResult:
    case_id: str
    passed: bool
    expected: dict[str, Any]
    actual: dict[str, Any]
    mismatches: list[str] = field(default_factory=list)
    description: str | None = None
    explanation: PolicyExplanation | None = None

    def to_payload(self) -> dict[str, Any]:
        payload = {
            "case_id": self.case_id,
            "passed": self.passed,
            "expected": self.expected,
            "actual": self.actual,
            "mismatches": self.mismatches,
        }
        if self.description:
            payload["description"] = self.description
        if self.explanation is not None:
            payload["explanation"] = self.explanation.to_payload()
        return payload


@dataclass(slots=True)
class PolicyTestRun:
    policy_path: Path
    cases_path: Path
    results: list[PolicyTestCaseResult] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for result in self.results if result.passed)

    @property
    def failed(self) -> int:
        return sum(1 for result in self.results if not result.passed)

    def to_payload(self) -> dict[str, Any]:
        return {
            "policy_path": str(self.policy_path),
            "cases_path": str(self.cases_path),
            "case_count": len(self.results),
            "passed": self.passed,
            "failed": self.failed,
            "results": [result.to_payload() for result in self.results],
        }


def build_policy_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect DualKey policy decisions")
    subcommands = parser.add_subparsers(dest="command", required=True)

    eval_parser = subcommands.add_parser("eval", help="Evaluate one action against a policy")
    eval_parser.add_argument("--policy", required=True, help="Path to a DualKey policy YAML file")
    source_group = eval_parser.add_mutually_exclusive_group()
    source_group.add_argument("--action-file", default=None, help="Path to an action JSON or YAML payload")
    source_group.add_argument("--action-json", default=None, help="Inline action JSON payload")
    eval_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="How to print the evaluation result",
    )
    eval_parser.add_argument(
        "--output",
        default=None,
        help="Write the rendered evaluation output to a file instead of stdout",
    )

    test_parser = subcommands.add_parser("test", help="Run a suite of action fixtures against a policy")
    test_parser.add_argument("--policy", required=True, help="Path to a DualKey policy YAML file")
    test_parser.add_argument("--cases", required=True, help="Path to a JSON or YAML cases file")
    test_parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Stop after the first failing case",
    )
    test_parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="How to print the test results",
    )
    test_parser.add_argument(
        "--output",
        default=None,
        help="Write the rendered test results to a file instead of stdout",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_policy_cli_parser()
    args = parser.parse_args(argv)

    if args.command == "eval":
        policy = load_policy(Path(args.policy))
        action_payload = _load_action_payload(args)
        explanation = policy.explain(action_payload)
        output = _render_explanation(explanation, policy_path=Path(args.policy), output_format=args.format)
        exit_code = 0
    elif args.command == "test":
        policy = load_policy(Path(args.policy))
        run = _run_policy_test(
            policy,
            policy_path=Path(args.policy),
            cases_path=Path(args.cases),
            fail_fast=bool(args.fail_fast),
        )
        output = _render_test_run(run, output_format=args.format)
        exit_code = 0 if run.failed == 0 else 1
    else:
        parser.error(f"Unsupported command: {args.command}")

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output, encoding="utf-8")
    elif output:
        print(output)
    return exit_code


def _load_action_payload(args: Any) -> dict[str, Any]:
    if args.action_json is not None:
        raw = args.action_json
    elif args.action_file is not None:
        raw = Path(args.action_file).read_text(encoding="utf-8")
    else:
        raw = sys.stdin.read()
        if not raw.strip():
            raise SystemExit("No action payload provided. Pass --action-file, --action-json, or pipe JSON/YAML on stdin.")

    payload = yaml.safe_load(raw)
    if not isinstance(payload, dict):
        raise SystemExit("Action payload must be a JSON/YAML object.")
    return payload


def _render_explanation(explanation: PolicyExplanation, *, policy_path: Path, output_format: str) -> str:
    if output_format == "json":
        return json.dumps(
            {
                "policy_path": str(policy_path),
                **explanation.to_payload(),
            },
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
    return _render_explanation_text(explanation, policy_path=policy_path)


def _render_explanation_text(explanation: PolicyExplanation, *, policy_path: Path) -> str:
    lines = [
        f"Policy: {policy_path}",
        f"Decision: {explanation.outcome.decision}",
        f"Matched rule: {explanation.outcome.rule_id}",
        f"Reason: {explanation.outcome.reason}",
        "",
        "Action:",
    ]
    lines.extend(f"- {line}" for line in explanation.action.preview())
    lines.extend(["", "Rule trace:"])
    for index, trace in enumerate(explanation.rules, start=1):
        status = "matched" if trace.matched else "skipped" if trace.skipped else "no-match"
        lines.append(f"{index}. {trace.rule_id} -> {status} ({trace.decision})")
        lines.append(f"   {trace.summary}")
        for check in trace.checks:
            prefix = "+" if check.matched else "x"
            lines.append(f"   {prefix} {check.detail}")
    return "\n".join(lines)


def _run_policy_test(policy: Any, *, policy_path: Path, cases_path: Path, fail_fast: bool) -> PolicyTestRun:
    cases = _load_cases(cases_path)
    results: list[PolicyTestCaseResult] = []
    for index, case in enumerate(cases, start=1):
        case_id = str(case.get("id", f"case_{index}"))
        description = case.get("description")
        action = case.get("action")
        expect = case.get("expect", {})
        if not isinstance(action, dict):
            raise SystemExit(f"Case '{case_id}' is missing an object-valued 'action'.")
        if not isinstance(expect, dict):
            raise SystemExit(f"Case '{case_id}' is missing an object-valued 'expect'.")

        explanation = policy.explain(action)
        result = _evaluate_policy_case(
            case_id=case_id,
            description=str(description) if description is not None else None,
            explanation=explanation,
            expect=expect,
        )
        results.append(result)
        if fail_fast and not result.passed:
            break
    return PolicyTestRun(policy_path=policy_path, cases_path=cases_path, results=results)


def _load_cases(path: Path) -> list[dict[str, Any]]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        cases = payload.get("cases")
    else:
        cases = payload
    if not isinstance(cases, list):
        raise SystemExit("Cases payload must be a list or an object with a 'cases' list.")
    normalized: list[dict[str, Any]] = []
    for case in cases:
        if not isinstance(case, dict):
            raise SystemExit("Each case entry must be an object.")
        normalized.append(dict(case))
    return normalized


def _evaluate_policy_case(
    *,
    case_id: str,
    description: str | None,
    explanation: PolicyExplanation,
    expect: dict[str, Any],
) -> PolicyTestCaseResult:
    actual = {
        "decision": explanation.outcome.decision,
        "rule_id": explanation.outcome.rule_id,
        "reason": explanation.outcome.reason,
    }
    mismatches: list[str] = []
    for field_name in ("decision", "rule_id"):
        expected = expect.get(field_name)
        if expected is not None and actual[field_name] != expected:
            mismatches.append(
                f"expected {field_name}={expected!r}, got {actual[field_name]!r}"
            )

    expected_reason_contains = expect.get("reason_contains")
    if expected_reason_contains is not None:
        needles = (
            [str(item) for item in expected_reason_contains]
            if isinstance(expected_reason_contains, list)
            else [str(expected_reason_contains)]
        )
        for needle in needles:
            if needle not in actual["reason"]:
                mismatches.append(f"expected reason to contain {needle!r}, got {actual['reason']!r}")

    return PolicyTestCaseResult(
        case_id=case_id,
        description=description,
        passed=not mismatches,
        expected=dict(expect),
        actual=actual,
        mismatches=mismatches,
        explanation=explanation,
    )


def _render_test_run(run: PolicyTestRun, *, output_format: str) -> str:
    if output_format == "json":
        return json.dumps(run.to_payload(), ensure_ascii=True, indent=2, sort_keys=True)
    return _render_test_run_text(run)


def _render_test_run_text(run: PolicyTestRun) -> str:
    lines = [
        f"Policy: {run.policy_path}",
        f"Cases: {run.cases_path}",
        f"Summary: {run.passed} passed, {run.failed} failed, {len(run.results)} total",
    ]
    for index, result in enumerate(run.results, start=1):
        status = "PASS" if result.passed else "FAIL"
        label = f"{index}. {result.case_id} -> {status}"
        if result.description:
            label += f" ({result.description})"
        lines.extend(["", label])
        lines.append(
            "   expected: "
            + _format_expected_summary(result.expected)
        )
        lines.append(
            "   actual: "
            + f"decision={result.actual['decision']!r} rule_id={result.actual['rule_id']!r}"
        )
        if result.mismatches:
            for mismatch in result.mismatches:
                lines.append(f"   x {mismatch}")
        elif result.explanation is not None:
            lines.append(f"   + {result.explanation.outcome.reason}")
    return "\n".join(lines)


def _format_expected_summary(expect: dict[str, Any]) -> str:
    if not expect:
        return "(no expectations)"
    parts: list[str] = []
    for key in ("decision", "rule_id", "reason_contains"):
        if key in expect:
            parts.append(f"{key}={expect[key]!r}")
    return " ".join(parts) if parts else "(no expectations)"


if __name__ == "__main__":
    raise SystemExit(main())
