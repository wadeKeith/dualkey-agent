from __future__ import annotations

from collections.abc import Callable, Mapping
import inspect
from pathlib import Path
from typing import Any

from dualkey.approvals import ApprovalHandler, ConsoleApprover
from dualkey.models import ActionEnvelope, ApprovalDecision, AuthorizationResult
from dualkey.policy import Policy, load_policy
from dualkey.receipts import ReceiptSettings, ReceiptSigner, ReceiptStore, build_receipt


TARGET_KEYS = (
    "url",
    "path",
    "file_name",
    "file_path",
    "selector",
    "query",
    "index",
    "text",
)
SECRET_MARKERS = (".env", "/.ssh/", "id_rsa", "secret", "token", "api_key", "password")
PAYMENT_MARKERS = ("pay", "checkout", "purchase", "payment", "submit")


class BrowserUseGuard:
    def __init__(
        self,
        policy: Policy,
        *,
        approval_mode: str = "tty",
        approver: ApprovalHandler | None = None,
        receipt_store: ReceiptStore | None = None,
        receipt_settings: ReceiptSettings | None = None,
        signer: ReceiptSigner | None = None,
        blocked_result_factory: Callable[[str], Any] | None = None,
    ) -> None:
        self.policy = policy
        self.approval_mode = approval_mode
        self.approver = approver
        self.receipt_settings = receipt_settings or getattr(receipt_store, "settings", None) or ReceiptSettings.from_env()
        self.receipt_store = receipt_store or ReceiptStore(
            ".dualkey/browser-use-receipts.jsonl",
            settings=self.receipt_settings,
        )
        if receipt_store is not None and hasattr(self.receipt_store, "settings"):
            self.receipt_store.settings = self.receipt_settings
        self.signer = signer or ReceiptSigner()
        self.blocked_result_factory = blocked_result_factory or self._default_blocked_result_factory

    def install(self, tools: Any) -> Any:
        registry = getattr(tools, "registry", None)
        if registry is None or not hasattr(registry, "execute_action"):
            raise TypeError("browser-use adapter expects a tools object with registry.execute_action")
        if getattr(registry, "_dualkey_browser_use_guard", None) is not None:
            return tools

        original_execute_action = registry.execute_action
        guard = self

        async def guarded_execute_action(
            action_name: str,
            params: dict,
            browser_session: Any | None = None,
            page_extraction_llm: Any | None = None,
            file_system: Any | None = None,
            sensitive_data: dict[str, Any] | None = None,
            available_file_paths: list[str] | None = None,
            extraction_schema: dict | None = None,
        ) -> Any:
            registry_definition = getattr(registry, "registry", None)
            registered_actions = getattr(registry_definition, "actions", {})
            registered_action = registered_actions.get(action_name)
            action = await guard._build_action_envelope(
                action_name=action_name,
                params=params,
                registered_action=registered_action,
                browser_session=browser_session,
                sensitive_data=sensitive_data,
                available_file_paths=available_file_paths,
            )
            authorization = await guard._authorize(action)
            if not authorization.allowed:
                receipt = build_receipt(
                    action=action,
                    authorization=authorization,
                    status="blocked",
                    error=f"blocked by {authorization.policy_outcome.rule_id}",
                    signer=guard.signer,
                    settings=guard.receipt_settings,
                )
                guard.receipt_store.append(receipt)
                return guard.blocked_result_factory(
                    f"DualKey blocked '{action_name}' with decision "
                    f"'{authorization.final_decision}' via rule '{authorization.policy_outcome.rule_id}'."
                )

            result = await original_execute_action(
                action_name,
                params,
                browser_session=browser_session,
                page_extraction_llm=page_extraction_llm,
                file_system=file_system,
                sensitive_data=sensitive_data,
                available_file_paths=available_file_paths,
                extraction_schema=extraction_schema,
            )
            result_error = _extract_result_error(result)
            receipt = build_receipt(
                action=action,
                authorization=authorization,
                status="tool_error" if result_error else "executed",
                result=result,
                error=result_error,
                signer=guard.signer,
                settings=guard.receipt_settings,
            )
            guard.receipt_store.append(receipt)
            return result

        registry._dualkey_original_execute_action = original_execute_action
        registry._dualkey_browser_use_guard = self
        registry.execute_action = guarded_execute_action
        return tools

    def uninstall(self, tools: Any) -> Any:
        registry = getattr(tools, "registry", None)
        original_execute_action = getattr(registry, "_dualkey_original_execute_action", None)
        if registry is not None and original_execute_action is not None:
            registry.execute_action = original_execute_action
            delattr(registry, "_dualkey_original_execute_action")
            delattr(registry, "_dualkey_browser_use_guard")
        return tools

    async def _build_action_envelope(
        self,
        *,
        action_name: str,
        params: Mapping[str, Any],
        registered_action: Any,
        browser_session: Any | None,
        sensitive_data: dict[str, Any] | None,
        available_file_paths: list[str] | None,
    ) -> ActionEnvelope:
        page_url = await _get_page_url(browser_session)
        sanitized_args = _sanitize_value(params)
        target = _extract_target(params)
        risk = _derive_risk(
            action_name=action_name,
            params=params,
            page_url=page_url,
            target=target,
            sensitive_data=sensitive_data,
        )
        metadata = {
            "page_url": page_url,
            "action_description": getattr(registered_action, "description", None),
            "domains": getattr(registered_action, "domains", None),
            "terminates_sequence": getattr(registered_action, "terminates_sequence", None),
            "has_sensitive_data": bool(sensitive_data),
            "available_file_paths": list(available_file_paths or []),
        }
        session_id = getattr(browser_session, "id", None) or "browser-use-session"
        return ActionEnvelope(
            actor="browser-use",
            surface="browser-use",
            tool=action_name,
            intent=_derive_intent(action_name, params),
            target=target,
            args=sanitized_args,
            risk=sorted(risk),
            session_id=str(session_id),
            trace_id=f"{session_id}:{action_name}",
            metadata={key: value for key, value in metadata.items() if value is not None},
        )

    async def _authorize(self, action: ActionEnvelope) -> AuthorizationResult:
        outcome = self.policy.evaluate(action)
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

        approval = self._request_second_key(action)
        return AuthorizationResult(
            allowed=approval.approved,
            final_decision="ask->approved" if approval.approved else "ask->rejected",
            policy_outcome=outcome,
            approved_by=approval.approver,
            approval_note=approval.note,
            approved_at=approval.approved_at,
        )

    def _request_second_key(self, action: ActionEnvelope) -> ApprovalDecision:
        if self.approval_mode == "auto-approve":
            return ApprovalDecision(approved=True, approver="dualkey:auto", note="auto-approved by browser-use adapter")
        if self.approval_mode == "auto-deny":
            return ApprovalDecision(approved=False, approver="dualkey:auto", note="auto-denied by browser-use adapter")

        approver = self.approver or self._build_tty_approver()
        if approver is None:
            return ApprovalDecision(
                approved=False,
                approver="dualkey:unavailable",
                note="no second-key approval surface available",
            )
        outcome = self.policy.evaluate(action)
        return approver.review(action, outcome)

    def _build_tty_approver(self) -> ApprovalHandler | None:
        if self.approval_mode not in {"tty", "auto"}:
            return None
        try:
            stdin = open("/dev/tty", "r", encoding="utf-8")
            stdout = open("/dev/tty", "w", encoding="utf-8")
        except OSError:
            return None
        return ConsoleApprover(auto_approve=False, identity="human:tty", stdin=stdin, stdout=stdout)

    def _default_blocked_result_factory(self, error_message: str) -> Any:
        try:
            from browser_use.agent.views import ActionResult  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "browser-use is not installed and no blocked_result_factory was provided"
            ) from exc
        return ActionResult(error=error_message)


def guard_browser_use_tools(
    tools: Any,
    *,
    policy: str | Path | Policy,
    approval_mode: str = "tty",
    approver: ApprovalHandler | None = None,
    receipts_path: str | Path = ".dualkey/browser-use-receipts.jsonl",
    receipt_settings: ReceiptSettings | None = None,
    signer: ReceiptSigner | None = None,
    blocked_result_factory: Callable[[str], Any] | None = None,
) -> Any:
    guard = BrowserUseGuard(
        load_policy(policy),
        approval_mode=approval_mode,
        approver=approver,
        receipt_store=ReceiptStore(receipts_path, settings=receipt_settings),
        receipt_settings=receipt_settings,
        signer=signer,
        blocked_result_factory=blocked_result_factory,
    )
    return guard.install(tools)


async def _get_page_url(browser_session: Any | None) -> str | None:
    if browser_session is None:
        return None
    getter = getattr(browser_session, "get_current_page_url", None)
    if getter is None:
        return None
    result = getter()
    if inspect.isawaitable(result):
        return await result
    return result


def _derive_intent(action_name: str, params: Mapping[str, Any]) -> str:
    if action_name in {"search", "extract", "find_text", "find_elements", "read_file", "screenshot"}:
        return "read"
    if action_name in {"navigate", "go_back", "wait", "switch", "close", "scroll"}:
        return "navigate"
    if action_name in {"click", "select_dropdown", "input", "upload_file", "send_keys"}:
        return "write"
    if action_name in {"write_file", "replace_file"}:
        return "write"
    if action_name == "evaluate":
        return "execute"
    if "url" in params:
        return "navigate"
    return "invoke"


def _derive_risk(
    *,
    action_name: str,
    params: Mapping[str, Any],
    page_url: str | None,
    target: str | None,
    sensitive_data: Mapping[str, Any] | None,
) -> set[str]:
    risk: set[str] = {"browser"}
    if action_name in {"navigate", "search", "extract", "evaluate"}:
        risk.add("open-world")
    if action_name in {"write_file", "replace_file", "input", "upload_file", "click", "select_dropdown"}:
        risk.add("write")
    if action_name == "evaluate":
        risk.add("script")
    if action_name == "upload_file":
        risk.add("filesystem")
    if action_name in {"close", "go_back"}:
        risk.add("destructive")
    if sensitive_data:
        risk.add("sensitive-session")

    for _, value in _iter_strings(params):
        lowered = value.lower()
        if any(marker in lowered for marker in SECRET_MARKERS):
            risk.update({"secrets", "critical-file"})
        if any(marker in lowered for marker in PAYMENT_MARKERS):
            risk.add("payment")
        if lowered.startswith("http://") or lowered.startswith("https://"):
            risk.add("network")

    if page_url:
        lowered_url = page_url.lower()
        if any(marker in lowered_url for marker in PAYMENT_MARKERS):
            risk.add("payment")
        if lowered_url.startswith("http://") or lowered_url.startswith("https://"):
            risk.add("network")

    if target:
        lowered_target = str(target).lower()
        if any(marker in lowered_target for marker in SECRET_MARKERS):
            risk.update({"secrets", "critical-file"})
        if any(marker in lowered_target for marker in PAYMENT_MARKERS):
            risk.add("payment")

    return risk


def _extract_target(params: Mapping[str, Any]) -> str | None:
    for key in TARGET_KEYS:
        value = params.get(key)
        if value is not None:
            return str(value)
    return None


def _sanitize_value(value: Any, key: str | None = None) -> Any:
    if isinstance(value, Mapping):
        return {item_key: _sanitize_value(item_value, key=item_key) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [_sanitize_value(item) for item in value]
    if isinstance(value, str):
        if key and any(marker in key.lower() for marker in ("token", "secret", "password", "api_key")):
            return "***"
        if len(value) > 500:
            return value[:497] + "..."
    return value


def _extract_result_error(result: Any) -> str | None:
    if result is None:
        return None
    if isinstance(result, Mapping):
        error = result.get("error")
        return str(error) if error else None
    error = getattr(result, "error", None)
    return str(error) if error else None


def _iter_strings(value: Any, prefix: str = "") -> list[tuple[str, str]]:
    if isinstance(value, Mapping):
        output: list[tuple[str, str]] = []
        for key, item in value.items():
            next_prefix = f"{prefix}.{key}" if prefix else str(key)
            output.extend(_iter_strings(item, next_prefix))
        return output
    if isinstance(value, list):
        output: list[tuple[str, str]] = []
        for index, item in enumerate(value):
            next_prefix = f"{prefix}.{index}" if prefix else str(index)
            output.extend(_iter_strings(item, next_prefix))
        return output
    if isinstance(value, str):
        return [(prefix, value)]
    return []
