from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from dualkey.browser_use_adapter import BrowserUseGuard, guard_browser_use_tools
from dualkey.policy import Policy


class FakeBrowserSession:
    def __init__(self, url: str) -> None:
        self._url = url
        self.id = "browser-session-1"

    async def get_current_page_url(self) -> str:
        return self._url


class FakeRegistry:
    def __init__(self) -> None:
        self.registry = SimpleNamespace(
            actions={
                "click": SimpleNamespace(
                    description="Click a DOM element",
                    domains=["shop.example.com"],
                    terminates_sequence=False,
                ),
                "write_file": SimpleNamespace(
                    description="Write a local file",
                    domains=[],
                    terminates_sequence=False,
                ),
                "evaluate": SimpleNamespace(
                    description="Run JavaScript in the page",
                    domains=["shop.example.com"],
                    terminates_sequence=False,
                ),
            }
        )
        self.calls: list[tuple[str, dict, Any | None]] = []

    async def execute_action(
        self,
        action_name: str,
        params: dict,
        browser_session: Any | None = None,
        **_: Any,
    ) -> dict[str, object]:
        self.calls.append((action_name, params, browser_session))
        if action_name == "evaluate":
            return {"ok": False, "error": "script blocked by page CSP"}
        return {"ok": True, "action": action_name, "params": params}


class FakeTools:
    def __init__(self) -> None:
        self.registry = FakeRegistry()


def read_receipts(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_browser_use_blocks_secret_write(tmp_path: Path) -> None:
    receipts = tmp_path / "browser-use.jsonl"
    policy = Policy.from_mapping(
        {
            "default_decision": "allow",
            "rules": [
                {
                    "id": "block_secret_write",
                    "decision": "deny",
                    "when": {
                        "actor": "browser-use",
                        "tool_in": ["write_file"],
                        "target_glob": "*.env",
                    },
                }
            ],
        }
    )
    tools = FakeTools()
    guard = BrowserUseGuard(
        policy,
        approval_mode="auto-deny",
        receipt_store=SimpleNamespace(append=lambda receipt: receipts.write_text(json.dumps(receipt.to_payload()) + "\n", encoding="utf-8")),
        blocked_result_factory=lambda error: {"error": error},
    )
    guard.install(tools)

    result = asyncio.run(
        tools.registry.execute_action(
            "write_file",
            {"path": "/repo/.env", "content": "TOKEN=secret"},
            browser_session=FakeBrowserSession("https://docs.browser-use.com"),
        )
    )

    assert "DualKey blocked" in result["error"]
    assert tools.registry.calls == []
    payload = json.loads(receipts.read_text(encoding="utf-8").strip())
    assert payload["decision"] == "deny"
    assert payload["status"] == "blocked"


def test_browser_use_checkout_click_asks_and_forwards(tmp_path: Path) -> None:
    receipts_path = tmp_path / "browser-use.jsonl"
    policy = Policy.from_mapping(
        {
            "default_decision": "allow",
            "rules": [
                {
                    "id": "checkout_click",
                    "decision": "ask",
                    "when": {
                        "actor": "browser-use",
                        "tool": "click",
                        "metadata_glob": {"page_url": "https://shop.example.com/checkout*"},
                        "arg_glob": {"selector": "*pay*"},
                    },
                }
            ],
        }
    )
    tools = FakeTools()
    guard_browser_use_tools(
        tools,
        policy=policy,
        approval_mode="auto-approve",
        receipts_path=receipts_path,
        blocked_result_factory=lambda error: {"error": error},
    )

    result = asyncio.run(
        tools.registry.execute_action(
            "click",
            {"selector": "button#pay-now"},
            browser_session=FakeBrowserSession("https://shop.example.com/checkout/review"),
        )
    )

    assert result["ok"] is True
    assert tools.registry.calls[0][0] == "click"
    receipt = read_receipts(receipts_path)[0]
    assert receipt["decision"] == "ask->approved"
    assert receipt["status"] == "executed"
    assert receipt["approved_by"] == "dualkey:auto"


def test_browser_use_tool_error_is_receipted_and_uninstall_restores_original(tmp_path: Path) -> None:
    receipts_path = tmp_path / "browser-use.jsonl"
    policy = Policy.from_mapping({"default_decision": "allow", "rules": []})
    tools = FakeTools()
    original = tools.registry.execute_action
    guard = BrowserUseGuard(
        policy,
        approval_mode="auto-approve",
        blocked_result_factory=lambda error: {"error": error},
    )
    guard.receipt_store.path = receipts_path
    guard.install(tools)

    result = asyncio.run(
        tools.registry.execute_action(
            "evaluate",
            {"expression": "window.localStorage.clear()"},
            browser_session=FakeBrowserSession("https://shop.example.com/cart"),
        )
    )

    assert result["error"] == "script blocked by page CSP"
    receipt = read_receipts(receipts_path)[0]
    assert receipt["status"] == "tool_error"
    guard.uninstall(tools)
    assert tools.registry.execute_action.__self__ is original.__self__
    assert tools.registry.execute_action.__func__ is original.__func__
