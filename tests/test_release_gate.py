from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "release_gate.py"
ISSUE_TEMPLATE = ROOT / ".github" / "ISSUE_TEMPLATE" / "release-checklist.md"


def _run_release_gate(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        text=True,
        capture_output=True,
        check=True,
    )


def test_release_gate_markdown_renders_checklist() -> None:
    process = _run_release_gate("--status", "passed")

    assert "# DualKey Release Gate" in process.stdout
    assert "Status: `passed`" in process.stdout
    assert "- [x] Unit tests" in process.stdout
    assert "python scripts/mcp_proxy_smoke.py" in process.stdout


def test_release_gate_json_includes_all_checks() -> None:
    process = _run_release_gate("--format", "json", "--status", "pending")

    payload = json.loads(process.stdout)
    assert payload["title"] == "DualKey Release Gate"
    assert payload["status"] == "pending"
    assert len(payload["checks"]) == 8
    assert payload["checks"][0]["name"] == "Unit tests"
    assert payload["checks"][-1]["name"] == "OpenHands real SDK compatibility"


def test_release_gate_can_write_output_file(tmp_path: Path) -> None:
    output_path = tmp_path / "release-gate.md"

    _run_release_gate("--status", "passed", "--output", str(output_path))

    content = output_path.read_text(encoding="utf-8")
    assert "# DualKey Release Gate" in content
    assert "- [x] Claude Code hook CLI smoke" in content


def test_release_gate_issue_template_matches_checked_in_template() -> None:
    process = _run_release_gate("--format", "issue-template")

    assert process.stdout == ISSUE_TEMPLATE.read_text(encoding="utf-8") + "\n"
    assert "## Release metadata" in process.stdout
    assert "- [ ] MCP proxy CLI smoke" in process.stdout
    assert "- [ ] Packaging smoke" in process.stdout
