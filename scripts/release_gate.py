from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


CHECKS: tuple[dict[str, str], ...] = (
    {
        "section": "Core",
        "name": "Unit tests",
        "command": "python -m pytest -q",
        "description": "Run the core DualKey test suite on Python 3.11 and 3.12.",
        "source": "ci:test",
    },
    {
        "section": "Core",
        "name": "Policy fixture regressions",
        "command": "dualkey-policy test --policy policy/examples/<name>.yaml --cases policy/examples/<name>-tests.yaml --fail-fast",
        "description": "Verify every shipped example policy still matches its expected decisions.",
        "source": "ci:test",
    },
    {
        "section": "Core",
        "name": "Receipt integrity smoke",
        "command": "python scripts/verify_smoke.py",
        "description": "Confirm dualkey-verify still accepts valid stores and rejects tampered stores and bundles.",
        "source": "ci:test",
    },
    {
        "section": "Core",
        "name": "Packaging smoke",
        "command": "python scripts/package_smoke.py",
        "description": "Build the sdist and wheel, then run twine check against the generated artifacts.",
        "source": "ci:test",
    },
    {
        "section": "Adapters",
        "name": "Claude Code hook CLI smoke",
        "command": "python scripts/claude_hook_smoke.py",
        "description": "Exercise the installed dualkey-claude-hook entrypoint with deny and allow payloads.",
        "source": "ci:adapter-compat",
    },
    {
        "section": "Adapters",
        "name": "MCP proxy CLI smoke",
        "command": "python scripts/mcp_proxy_smoke.py",
        "description": "Drive the installed dualkey-mcp-proxy through initialize, tools/list, blocked tool calls, and elicitation approval.",
        "source": "ci:adapter-compat",
    },
    {
        "section": "Adapters",
        "name": "browser-use runtime compatibility",
        "command": "python -m pytest -q tests/test_browser_use_runtime_compat.py",
        "description": "Check the public browser-use Tools registry and ActionResult import path against the real package.",
        "source": "ci:adapter-compat",
    },
    {
        "section": "Adapters",
        "name": "OpenHands real SDK compatibility",
        "command": "python -m pytest -q tests/test_openhands_sdk_integration.py",
        "description": "Verify the real OpenHands LocalConversation boundary and confirmation receipts on Python 3.12.",
        "source": "ci:adapter-compat",
    },
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Render the DualKey release gate checklist")
    parser.add_argument(
        "--status",
        choices=["pending", "passed"],
        default="pending",
        help="Whether to render the checklist as pending or passed",
    )
    parser.add_argument(
        "--format",
        choices=["markdown", "json", "issue-template"],
        default="markdown",
        help="Output format",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Write the rendered checklist to a file instead of stdout",
    )
    return parser


def render_release_gate(*, status: str, output_format: str) -> str:
    payload = {
        "title": "DualKey Release Gate",
        "status": status,
        "checks": [
            {
                **item,
                "status": status,
            }
            for item in CHECKS
        ],
    }
    if output_format == "json":
        return json.dumps(payload, indent=2, sort_keys=True)
    if output_format == "issue-template":
        return _render_issue_template(payload)
    return _render_markdown(payload)


def _render_markdown(payload: dict[str, Any]) -> str:
    checked = "x" if payload["status"] == "passed" else " "
    lines = [
        "# DualKey Release Gate",
        "",
        f"Status: `{payload['status']}`",
        "",
        "A release is open only when every item below is green in CI.",
        "",
    ]
    current_section: str | None = None
    for item in payload["checks"]:
        if item["section"] != current_section:
            current_section = item["section"]
            lines.extend([f"## {current_section}", ""])
        lines.append(f"- [{checked}] {item['name']}")
        lines.append(f"  Command: `{item['command']}`")
        lines.append(f"  Scope: {item['description']}")
        lines.append(f"  Source: `{item['source']}`")
    lines.append("")
    return "\n".join(lines)


def _render_issue_template(payload: dict[str, Any]) -> str:
    checked = "x" if payload["status"] == "passed" else " "
    lines = [
        "---",
        "name: Release Checklist",
        "about: Track the required checks before cutting a DualKey release.",
        'title: "release: <version>"',
        "labels: release",
        "assignees: ''",
        "---",
        "",
        "# DualKey Release Checklist",
        "",
        "Release target: `<version>`",
        "",
        "## Release metadata",
        "",
        "- [ ] Version number is final.",
        "- [ ] Release notes / changelog entry are drafted.",
        "- [ ] Any migration or rollout notes are linked in this issue.",
        "",
        f"## Automated Gate (`{payload['status']}`)",
        "",
        "Copy the latest CI artifact or re-run `python3 scripts/release_gate.py --status passed` before checking boxes below.",
        "",
    ]
    current_section: str | None = None
    for item in payload["checks"]:
        if item["section"] != current_section:
            current_section = item["section"]
            lines.extend([f"### {current_section}", ""])
        lines.append(f"- [{checked}] {item['name']}")
        lines.append(f"  Command: `{item['command']}`")
        lines.append(f"  Scope: {item['description']}")
        lines.append(f"  Source: `{item['source']}`")
    lines.extend(
        [
            "",
            "## Approval",
            "",
            "- [ ] A maintainer confirmed the gate is green and the release can be cut.",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    output = render_release_gate(status=args.status, output_format=args.format)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output + ("\n" if not output.endswith("\n") else ""), encoding="utf-8")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
