import json
import os
from pathlib import Path
import subprocess
import sys

from dualkey.models import ActionEnvelope
from dualkey.policy import Policy, load_policy


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policy" / "examples" / "dualkey.yaml"
SRC = ROOT / "sdk" / "python" / "src"
EXAMPLE_CASES = [
    ("dualkey", "dualkey-tests"),
    ("claude-code", "claude-code-tests"),
    ("browser-use", "browser-use-tests"),
    ("mcp-proxy", "mcp-proxy-tests"),
    ("openhands", "openhands-tests"),
]


def test_secret_write_is_denied() -> None:
    policy = load_policy(POLICY_PATH)
    action = ActionEnvelope(
        actor="openhands",
        surface="shell",
        tool="filesystem.write",
        intent="write",
        target="/repo/.env",
        args={"path": "/repo/.env"},
        risk=["secrets", "write"],
    )

    outcome = policy.evaluate(action)

    assert outcome.decision == "deny"
    assert outcome.rule_id == "prod_and_secret_writes_are_denied"


def test_payment_click_requires_approval() -> None:
    policy = load_policy(POLICY_PATH)
    action = ActionEnvelope(
        actor="browser-use",
        surface="browser",
        tool="browser.click",
        intent="click",
        target="button#pay-now",
        args={"selector": "button#pay-now"},
        risk=["payment"],
    )

    outcome = policy.evaluate(action)

    assert outcome.decision == "ask"
    assert outcome.rule_id == "payment_click_requires_second_key"


def test_unknown_action_falls_back_to_default() -> None:
    policy = load_policy(POLICY_PATH)
    action = ActionEnvelope(
        actor="agent",
        surface="http",
        tool="webhook.post",
        intent="send",
        target="https://example.com",
    )

    outcome = policy.evaluate(action)

    assert outcome.decision == "ask"
    assert outcome.rule_id == "default"


def test_tool_glob_and_nested_arg_regex_match() -> None:
    policy = Policy.from_mapping(
        {
            "default_decision": "deny",
            "rules": [
                {
                    "id": "push_main",
                    "decision": "ask",
                    "when": {
                        "tool_glob": "B*",
                        "arg_regex": {
                            "command": r"(^|\s)git\s+push\s+\S+\s+main(\s|$)",
                        },
                    },
                }
            ],
        }
    )
    action = ActionEnvelope(
        actor="claude-code",
        surface="claude-code",
        tool="Bash",
        intent="execute",
        args={"command": "git push origin main"},
    )

    outcome = policy.evaluate(action)

    assert outcome.decision == "ask"
    assert outcome.rule_id == "push_main"


def test_nested_metadata_and_arg_exists_match() -> None:
    policy = Policy.from_mapping(
        {
            "default_decision": "deny",
            "rules": [
                {
                    "id": "permission_webfetch",
                    "decision": "allow",
                    "when": {
                        "metadata_equals": {"hook_event_name": "PermissionRequest"},
                        "metadata_exists": ["permission_suggestions.0.destination"],
                        "arg_exists": ["url"],
                        "arg_glob": {"url": "https://example.com*"},
                    },
                }
            ],
        }
    )
    action = ActionEnvelope(
        actor="claude-code",
        surface="claude-code",
        tool="WebFetch",
        intent="read",
        args={"url": "https://example.com/docs"},
        metadata={
            "hook_event_name": "PermissionRequest",
            "permission_suggestions": [{"destination": "session"}],
        },
    )

    outcome = policy.evaluate(action)

    assert outcome.decision == "allow"
    assert outcome.rule_id == "permission_webfetch"


def test_policy_explain_includes_failed_and_matched_checks() -> None:
    policy = load_policy(POLICY_PATH)
    action = ActionEnvelope(
        actor="openhands",
        surface="shell",
        tool="shell.exec",
        intent="execute",
        target="/repo/app.py",
        args={"command": "git push origin main"},
        risk=["git"],
    )

    explanation = policy.explain(action)

    assert explanation.outcome.decision == "ask"
    assert explanation.outcome.rule_id == "git_push_requires_second_key"
    assert explanation.rules[0].matched is False
    assert "intent expected 'read'" in explanation.rules[0].summary
    assert explanation.rules[1].matched is True
    assert any("command matched snippet 'git push'" in check.detail for check in explanation.rules[1].checks)
    assert explanation.rules[2].skipped is True


def test_policy_cli_can_evaluate_action_json(tmp_path: Path) -> None:
    action_path = tmp_path / "action.json"
    action_path.write_text(
        json.dumps(
            {
                "actor": "browser-use",
                "surface": "browser",
                "tool": "browser.click",
                "intent": "click",
                "target": "button#pay-now",
                "args": {"selector": "button#pay-now"},
                "risk": ["payment"],
            }
        ),
        encoding="utf-8",
    )

    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "dualkey.policy_cli",
            "eval",
            "--policy",
            str(POLICY_PATH),
            "--action-file",
            str(action_path),
            "--format",
            "json",
        ],
        text=True,
        capture_output=True,
        check=True,
        env={**os.environ, "PYTHONPATH": str(SRC)},
    )

    payload = json.loads(process.stdout)

    assert payload["outcome"]["decision"] == "ask"
    assert payload["outcome"]["rule_id"] == "payment_click_requires_second_key"
    assert payload["rules"][0]["matched"] is False
    assert payload["rules"][1]["matched"] is False
    assert payload["rules"][2]["matched"] is False
    assert payload["rules"][3]["matched"] is True


def test_policy_cli_can_run_cases_file(tmp_path: Path) -> None:
    cases_path = tmp_path / "cases.yaml"
    cases_path.write_text(
        """
cases:
  - id: pay_click
    action:
      actor: browser-use
      surface: browser
      tool: browser.click
      intent: click
      target: button#pay-now
      args:
        selector: button#pay-now
      risk: [payment]
    expect:
      decision: ask
      rule_id: payment_click_requires_second_key
  - id: default_path
    action:
      actor: agent
      surface: http
      tool: webhook.post
      intent: send
      target: https://example.com
    expect:
      decision: ask
      rule_id: default
        """.strip(),
        encoding="utf-8",
    )

    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "dualkey.policy_cli",
            "test",
            "--policy",
            str(POLICY_PATH),
            "--cases",
            str(cases_path),
            "--format",
            "json",
        ],
        text=True,
        capture_output=True,
        check=False,
        env={**os.environ, "PYTHONPATH": str(SRC)},
    )

    payload = json.loads(process.stdout)

    assert process.returncode == 0
    assert payload["passed"] == 2
    assert payload["failed"] == 0
    assert payload["results"][0]["case_id"] == "pay_click"
    assert payload["results"][0]["actual"]["rule_id"] == "payment_click_requires_second_key"
    assert payload["results"][1]["actual"]["rule_id"] == "default"


def test_policy_cli_test_returns_nonzero_for_failures(tmp_path: Path) -> None:
    cases_path = tmp_path / "failing-cases.yaml"
    cases_path.write_text(
        """
cases:
  - id: wrong_expectation
    action:
      actor: openhands
      surface: shell
      tool: filesystem.write
      intent: write
      target: /repo/.env
      args:
        path: /repo/.env
      risk: [secrets]
    expect:
      decision: allow
      rule_id: prod_and_secret_writes_are_denied
        """.strip(),
        encoding="utf-8",
    )

    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "dualkey.policy_cli",
            "test",
            "--policy",
            str(POLICY_PATH),
            "--cases",
            str(cases_path),
        ],
        text=True,
        capture_output=True,
        check=False,
        env={**os.environ, "PYTHONPATH": str(SRC)},
    )

    assert process.returncode == 1
    assert "wrong_expectation -> FAIL" in process.stdout
    assert "expected decision='allow', got 'deny'" in process.stdout


def test_repo_example_policy_cases_all_pass() -> None:
    for policy_name, cases_name in EXAMPLE_CASES:
        process = subprocess.run(
            [
                sys.executable,
                "-m",
                "dualkey.policy_cli",
                "test",
                "--policy",
                str(ROOT / "policy" / "examples" / f"{policy_name}.yaml"),
                "--cases",
                str(ROOT / "policy" / "examples" / f"{cases_name}.yaml"),
                "--format",
                "json",
            ],
            text=True,
            capture_output=True,
            check=False,
            env={**os.environ, "PYTHONPATH": str(SRC)},
        )
        payload = json.loads(process.stdout)
        assert process.returncode == 0, (policy_name, process.stdout, process.stderr)
        assert payload["failed"] == 0, payload
