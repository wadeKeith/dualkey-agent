from __future__ import annotations

import pytest


pytest.importorskip(
    "browser_use",
    reason="Install dualkey-agent[browser-use] to run real browser-use compatibility tests.",
)

from browser_use import Tools
from browser_use.agent.views import ActionResult

from dualkey.browser_use_adapter import BrowserUseGuard
from dualkey.policy import Policy


pytestmark = pytest.mark.browser_use_integration


def test_real_browser_use_tools_registry_is_guard_compatible() -> None:
    tools = Tools()
    original = tools.registry.execute_action
    guard = BrowserUseGuard(
        Policy.from_mapping({"default_decision": "allow", "rules": []}),
        approval_mode="auto-deny",
    )

    guard.install(tools)

    assert getattr(tools.registry, "_dualkey_browser_use_guard") is guard
    guard.uninstall(tools)
    assert tools.registry.execute_action.__self__ is original.__self__
    assert tools.registry.execute_action.__func__ is original.__func__


def test_real_browser_use_blocked_result_factory_returns_action_result() -> None:
    guard = BrowserUseGuard(
        Policy.from_mapping({"default_decision": "allow", "rules": []}),
        approval_mode="auto-deny",
    )

    result = guard._default_blocked_result_factory("blocked by dualkey")

    assert isinstance(result, ActionResult)
    assert getattr(result, "error", None) == "blocked by dualkey"
