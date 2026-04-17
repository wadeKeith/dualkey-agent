from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Callable, Mapping, Sequence
import inspect
import json
from pathlib import Path
import re
import shlex
from types import MethodType
from typing import Any

from dualkey.approvals import ApprovalHandler, ConsoleApprover
from dualkey.models import ActionEnvelope, ApprovalDecision, AuthorizationResult, PolicyOutcome, utc_now
from dualkey.policy import Policy, load_policy
from dualkey.receipts import ReceiptSettings, ReceiptSigner, ReceiptStore, build_receipt


SECRET_MARKERS = (".env", "/.ssh/", "id_rsa", "secret", "token", "api_key", "password")
GIT_PATH_MARKERS = ("/.git/", ".gitignore", ".gitmodules", ".gitattributes")
DESTRUCTIVE_COMMAND_RE = re.compile(
    r"(^|[;&|]\s*|\s)(rm\s+-rf|git\s+reset\s+--hard|git\s+clean\s+-fd|sudo\s+rm\b)"
)
NETWORK_COMMAND_RE = re.compile(
    r"(^|[;&|]\s*|\s)(curl|wget|ssh|scp|rsync|kubectl|docker|gh)\b"
)
READ_ONLY_SHELL_TOKENS = {
    "pwd",
    "ls",
    "cat",
    "find",
    "rg",
    "grep",
    "head",
    "tail",
    "wc",
    "stat",
    "which",
    "env",
    "printenv",
}
READ_ONLY_GIT_SUBCOMMANDS = {
    "status",
    "diff",
    "show",
    "log",
    "branch",
    "rev-parse",
    "remote",
    "grep",
    "ls-files",
    "tag",
}
WRITE_GIT_SUBCOMMANDS = {
    "add",
    "apply",
    "am",
    "checkout",
    "switch",
    "restore",
    "merge",
    "rebase",
    "cherry-pick",
    "commit",
    "reset",
    "clean",
    "mv",
    "rm",
    "push",
    "pull",
    "fetch",
    "clone",
    "init",
    "worktree",
    "submodule",
    "stash",
}
TERMINAL_TOOL_NAMES = {"terminaltool", "bashtool", "terminal", "bash"}
FILE_TOOL_NAMES = {"fileeditortool", "file_editor", "fileeditor"}
WAITING_FOR_CONFIRMATION = "waiting_for_confirmation"
RUNNING = "running"
IDLE = "idle"
NATIVE_CONFIRMATION_RULE_ID = "openhands:native_confirmation"


@dataclass(slots=True)
class _NativePendingAction:
    action_id: str
    tool_call_id: str | None
    correlation_key: str
    envelope: ActionEnvelope


class OpenHandsGuard:
    def __init__(
        self,
        policy: Policy,
        *,
        approval_mode: str = "tty",
        approver: ApprovalHandler | None = None,
        receipt_store: ReceiptStore | None = None,
        receipt_settings: ReceiptSettings | None = None,
        signer: ReceiptSigner | None = None,
        blocked_observation_factory: Callable[[Any, str], Any] | None = None,
    ) -> None:
        self.policy = policy
        self.approval_mode = approval_mode
        self.approver = approver
        self.receipt_settings = receipt_settings or getattr(receipt_store, "settings", None) or ReceiptSettings.from_env()
        self.receipt_store = receipt_store or ReceiptStore(
            ".dualkey/openhands-receipts.jsonl",
            settings=self.receipt_settings,
        )
        if receipt_store is not None and hasattr(self.receipt_store, "settings"):
            self.receipt_store.settings = self.receipt_settings
        self.signer = signer or ReceiptSigner()
        self.blocked_observation_factory = (
            blocked_observation_factory or self._default_blocked_observation_factory
        )
        self._patched_agents: dict[int, Any] = {}
        self._patched_conversations: dict[int, Any] = {}
        self._pending_native_actions: dict[str, _NativePendingAction] = {}
        self._pending_native_keys: dict[str, list[str]] = {}
        self._conversation_status: dict[int, str] = {}
        self._waiting_receipts_emitted: set[str] = set()
        self._approval_receipts_emitted: set[str] = set()

    def install_on_tools(self, tools: Any) -> Any:
        return self._install_on_tools_with_context(tools, context=None)

    def _install_on_tools_with_context(
        self,
        tools: Any,
        *,
        context: Mapping[str, Any] | None,
    ) -> Any:
        if isinstance(tools, Mapping):
            for name, tool in list(tools.items()):
                tools[name] = self._wrap_tool(tool, context=context)
            return tools
        if isinstance(tools, list):
            for index, tool in enumerate(list(tools)):
                tools[index] = self._wrap_tool(tool, context=context)
            return tools
        if isinstance(tools, tuple):
            return tuple(self._wrap_tool(tool, context=context) for tool in tools)
        if isinstance(tools, Sequence):
            return [self._wrap_tool(tool, context=context) for tool in tools]
        raise TypeError("OpenHands adapter expects a tools map or sequence of tool definitions")

    def install_on_agent(self, agent: Any) -> Any:
        if self._try_install_agent_tools(agent):
            return agent

        agent_id = id(agent)
        if agent_id in self._patched_agents:
            return agent

        original_init_state = getattr(agent, "init_state", None)
        if original_init_state is None or not callable(original_init_state):
            raise TypeError("OpenHands adapter expects an agent with init_state() or tools_map")

        guard = self

        if inspect.iscoroutinefunction(original_init_state):

            async def guarded_init_state(self_obj: Any, *args: Any, **kwargs: Any) -> Any:
                result = await original_init_state(*args, **kwargs)
                guard._try_install_agent_tools(self_obj)
                return result

        else:

            def guarded_init_state(self_obj: Any, *args: Any, **kwargs: Any) -> Any:
                result = original_init_state(*args, **kwargs)
                guard._try_install_agent_tools(self_obj)
                return result

        _safe_setattr(agent, "init_state", MethodType(guarded_init_state, agent))
        self._patched_agents[agent_id] = original_init_state
        return agent

    def install_on_conversation(self, conversation: Any) -> Any:
        conversation_id = id(conversation)
        if conversation_id in self._patched_conversations:
            return conversation

        self.install_on_agent(conversation.agent)
        self._try_bind_conversation_context(conversation)
        state = conversation.state
        self._conversation_status[conversation_id] = _normalize_status(
            getattr(state, "execution_status", "")
        )
        self._patch_state_callback(conversation, state)
        self._patch_reject_pending_actions(conversation)
        self._patched_conversations[conversation_id] = conversation
        return conversation

    def _try_install_agent_tools(self, agent: Any) -> bool:
        try:
            tools_map = agent.tools_map
        except Exception:
            return False
        self._install_on_tools_with_context(
            tools_map,
            context=_context_from_agent(agent),
        )
        return True

    def _wrap_tool(self, tool: Any, *, context: Mapping[str, Any] | None = None) -> Any:
        executor = getattr(tool, "executor", None)
        if executor is None:
            return tool
        if isinstance(executor, _WrappedOpenHandsExecutor):
            executor.bind_context(context)
            return tool
        wrapped_executor = _WrappedOpenHandsExecutor(
            self,
            tool,
            executor,
            context=context,
        )
        if hasattr(tool, "set_executor") and callable(tool.set_executor):
            replaced = tool.set_executor(wrapped_executor)
            if replaced is not None:
                wrapped_executor.tool = replaced
                return replaced
            return tool
        _safe_setattr(tool, "executor", wrapped_executor)
        return tool

    def _build_action_envelope(
        self,
        tool: Any,
        action: Any,
        *,
        context: Mapping[str, Any] | None = None,
    ) -> ActionEnvelope:
        tool_name = _tool_name(tool)
        payload = _action_payload(action)
        return self._make_action_envelope(
            tool_name=tool_name,
            payload=payload,
            tool=tool,
            action_type=action.__class__.__name__,
            context=context,
        )

    def _authorize(self, action: ActionEnvelope) -> AuthorizationResult:
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

        approval = self._request_second_key(action, outcome)
        return AuthorizationResult(
            allowed=approval.approved,
            final_decision="ask->approved" if approval.approved else "ask->rejected",
            policy_outcome=outcome,
            approved_by=approval.approver,
            approval_note=approval.note,
            approved_at=approval.approved_at,
        )

    def _request_second_key(self, action: ActionEnvelope, outcome: Any) -> ApprovalDecision:
        if self.approval_mode == "auto-approve":
            return ApprovalDecision(approved=True, approver="dualkey:auto", note="auto-approved by OpenHands adapter")
        if self.approval_mode == "auto-deny":
            return ApprovalDecision(approved=False, approver="dualkey:auto", note="auto-denied by OpenHands adapter")

        approver = self.approver or self._build_tty_approver()
        if approver is None:
            return ApprovalDecision(
                approved=False,
                approver="dualkey:unavailable",
                note="no second-key approval surface available",
            )
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

    def _default_blocked_observation_factory(self, tool: Any, error_message: str) -> Any:
        observation_type = getattr(tool, "observation_type", None)
        if observation_type is None:
            return {"error": error_message, "is_error": True}
        from_text = getattr(observation_type, "from_text", None)
        if callable(from_text):
            return from_text(error_message, is_error=True)
        return {"error": error_message, "is_error": True}

    def _make_action_envelope(
        self,
        *,
        tool_name: str,
        payload: Mapping[str, Any],
        tool: Any | None = None,
        action_type: str | None = None,
        action_id: str | None = None,
        tool_call_id: str | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> ActionEnvelope:
        tool_kind = _tool_kind(tool_name)
        target = _extract_target(tool_kind, payload)
        surface = _derive_surface(tool_kind, payload)
        intent = _derive_intent(tool_kind, payload)
        risk = _derive_risk(tool_kind, payload, target=target, intent=intent, surface=surface)
        session_id, context_metadata = _session_context(context)
        canonical_args = _canonicalize_matching_payload(payload)
        metadata = {
            "tool_name": tool_name,
            "tool_title": _tool_title(tool) if tool is not None else None,
            "action_kind": tool_kind,
            "action_type": action_type,
        }
        metadata.update(_derive_metadata(tool_kind, payload))
        metadata.update(context_metadata)
        if action_id is not None:
            metadata["openhands_action_id"] = action_id
        if tool_call_id is not None:
            metadata["openhands_tool_call_id"] = tool_call_id

        envelope = ActionEnvelope(
            actor="openhands",
            surface=surface,
            tool=tool_name,
            intent=intent,
            target=target,
            args=canonical_args,
            risk=sorted(risk),
            session_id=session_id,
            trace_id=_openhands_trace_id(
                tool_name=tool_name,
                payload=payload,
                tool_call_id=tool_call_id,
                fallback=action_type,
            ),
            metadata={key: value for key, value in metadata.items() if value is not None},
        )
        return self._align_with_native_confirmation(envelope)

    def _patch_state_callback(self, conversation: Any, state: Any) -> None:
        original_set_on_state_change = getattr(state, "set_on_state_change", None)
        if original_set_on_state_change is None or not callable(original_set_on_state_change):
            raise TypeError("OpenHands conversation state must expose set_on_state_change()")

        existing_callback = getattr(state, "_on_state_change", None)
        guard = self

        def compose_callback(user_callback: Any) -> Callable[[Any], None]:
            def wrapped(event: Any) -> None:
                if user_callback is not None:
                    user_callback(event)
                guard._handle_native_state_change(conversation, event)

            return wrapped

        def guarded_set_on_state_change(self_obj: Any, callback: Any) -> Any:
            return original_set_on_state_change(compose_callback(callback))

        _safe_setattr(state, "set_on_state_change", MethodType(guarded_set_on_state_change, state))
        original_set_on_state_change(compose_callback(existing_callback))

    def _patch_reject_pending_actions(self, conversation: Any) -> None:
        original_reject = getattr(conversation, "reject_pending_actions", None)
        if original_reject is None or not callable(original_reject):
            raise TypeError("OpenHands conversation must expose reject_pending_actions()")

        guard = self

        def guarded_reject_pending_actions(self_obj: Any, reason: str = "User rejected the action") -> Any:
            pending_actions = guard._get_pending_action_events(self_obj)
            result = original_reject(reason)
            guard._record_native_rejections(self_obj, pending_actions, reason)
            return result

        _safe_setattr(
            conversation,
            "reject_pending_actions",
            MethodType(guarded_reject_pending_actions, conversation),
        )

    def _handle_native_state_change(self, conversation: Any, event: Any) -> None:
        if getattr(event, "key", None) != "execution_status":
            return

        conversation_id = id(conversation)
        previous_status = self._conversation_status.get(conversation_id, "")
        new_status = _normalize_status(getattr(event, "value", ""))
        self._conversation_status[conversation_id] = new_status

        if new_status == WAITING_FOR_CONFIRMATION:
            self._record_native_waiting(conversation)
            return

        if previous_status == WAITING_FOR_CONFIRMATION and new_status == RUNNING:
            self._record_native_approvals(conversation)

    def _record_native_waiting(self, conversation: Any) -> None:
        for action_event in self._get_pending_action_events(conversation):
            pending = self._register_native_pending_action(conversation, action_event)
            if pending is None or pending.action_id in self._waiting_receipts_emitted:
                continue
            receipt = build_receipt(
                action=pending.envelope,
                authorization=_native_authorization_result("ask"),
                status="openhands_confirmation_waiting",
                result={
                    "status": WAITING_FOR_CONFIRMATION,
                    "tool_call_id": pending.tool_call_id,
                },
                signer=self.signer,
                settings=self.receipt_settings,
            )
            self.receipt_store.append(receipt)
            self._waiting_receipts_emitted.add(pending.action_id)

    def _record_native_approvals(self, conversation: Any) -> None:
        for action_event in self._get_pending_action_events(conversation):
            pending = self._register_native_pending_action(conversation, action_event)
            if pending is None or pending.action_id in self._approval_receipts_emitted:
                continue
            receipt = build_receipt(
                action=pending.envelope,
                authorization=_native_authorization_result(
                    "ask->approved",
                    approved_by="human:openhands",
                ),
                status="openhands_confirmation_approved",
                result={
                    "status": RUNNING,
                    "tool_call_id": pending.tool_call_id,
                },
                signer=self.signer,
                settings=self.receipt_settings,
            )
            self.receipt_store.append(receipt)
            self._approval_receipts_emitted.add(pending.action_id)

    def _record_native_rejections(
        self,
        conversation: Any,
        pending_actions: Sequence[Any],
        reason: str,
    ) -> None:
        for action_event in pending_actions:
            pending = self._register_native_pending_action(conversation, action_event)
            if pending is None:
                continue
            receipt = build_receipt(
                action=pending.envelope,
                authorization=_native_authorization_result(
                    "ask->rejected",
                    approved_by="human:openhands",
                ),
                status="openhands_confirmation_rejected",
                error=reason,
                signer=self.signer,
                settings=self.receipt_settings,
            )
            self.receipt_store.append(receipt)
            self._forget_native_pending_action(pending.action_id)

    def _get_pending_action_events(self, conversation: Any) -> list[Any]:
        state = conversation.state
        getter = getattr(state.__class__, "get_unmatched_actions", None)
        if callable(getter):
            return list(getter(state.events))
        bound_getter = getattr(state, "get_unmatched_actions", None)
        if callable(bound_getter):
            return list(bound_getter(state.events))
        return []

    def _register_native_pending_action(
        self,
        conversation: Any,
        action_event: Any,
    ) -> _NativePendingAction | None:
        action_id = _event_action_id(action_event)
        if action_id is None:
            return None
        existing = self._pending_native_actions.get(action_id)
        if existing is not None:
            return existing

        action = getattr(action_event, "action", None)
        if action is None:
            return None
        tool_name = str(getattr(action_event, "tool_name", ""))
        payload = _action_payload(action)
        tool_call_id = _event_tool_call_id(action_event)
        tool = _lookup_tool(conversation, tool_name)
        envelope = self._make_action_envelope(
            tool_name=tool_name,
            payload=payload,
            tool=tool,
            action_type=action.__class__.__name__,
            action_id=action_id,
            tool_call_id=tool_call_id,
            context=_context_from_conversation(conversation),
        )
        correlation_key = _native_correlation_key(tool_name, payload)
        pending = _NativePendingAction(
            action_id=action_id,
            tool_call_id=tool_call_id,
            correlation_key=correlation_key,
            envelope=envelope,
        )
        self._pending_native_actions[action_id] = pending
        self._pending_native_keys.setdefault(correlation_key, []).append(action_id)
        return pending

    def _align_with_native_confirmation(self, envelope: ActionEnvelope) -> ActionEnvelope:
        pending = None
        action_id = envelope.metadata.get("openhands_action_id")
        if action_id is not None:
            pending = self._pending_native_actions.get(str(action_id))
        if pending is None:
            correlation_key = _native_correlation_key(envelope.tool, envelope.args)
            candidate_ids = self._pending_native_keys.get(correlation_key, [])
            for candidate_id in candidate_ids:
                pending = self._pending_native_actions.get(candidate_id)
                if pending is not None:
                    break
        if pending is None:
            return envelope

        envelope.session_id = pending.envelope.session_id
        envelope.trace_id = pending.envelope.trace_id
        envelope.created_at = pending.envelope.created_at
        envelope.metadata = {**envelope.metadata, **pending.envelope.metadata}
        return envelope

    def _forget_native_pending_action(self, action_id: str | None) -> None:
        if action_id is None:
            return
        pending = self._pending_native_actions.pop(str(action_id), None)
        if pending is None:
            return
        action_ids = self._pending_native_keys.get(pending.correlation_key, [])
        remaining = [candidate for candidate in action_ids if candidate != pending.action_id]
        if remaining:
            self._pending_native_keys[pending.correlation_key] = remaining
        else:
            self._pending_native_keys.pop(pending.correlation_key, None)

    def _try_bind_conversation_context(self, conversation: Any) -> None:
        try:
            tools_map = conversation.agent.tools_map
        except Exception:
            return
        self._install_on_tools_with_context(
            tools_map,
            context=_context_from_conversation(conversation),
        )


class _WrappedOpenHandsExecutor:
    def __init__(
        self,
        guard: OpenHandsGuard,
        tool: Any,
        original_executor: Any,
        *,
        context: Mapping[str, Any] | None = None,
    ) -> None:
        self.guard = guard
        self.tool = tool
        self.original_executor = original_executor
        self._context: dict[str, Any] = {}
        self.bind_context(context)
        self._accepts_conversation = _executor_accepts_conversation(original_executor)

    def bind_context(self, context: Mapping[str, Any] | None) -> None:
        if not context:
            return
        for key, value in context.items():
            if value is not None:
                self._context[key] = value

    def __call__(self, action: Any, conversation: Any | None = None) -> Any:
        self.bind_context(_context_from_conversation(conversation))
        envelope = self.guard._build_action_envelope(
            self.tool,
            action,
            context=self._context,
        )
        authorization = self.guard._authorize(envelope)
        if not authorization.allowed:
            receipt = build_receipt(
                action=envelope,
                authorization=authorization,
                status="blocked",
                error=f"blocked by {authorization.policy_outcome.rule_id}",
                signer=self.guard.signer,
                settings=self.guard.receipt_settings,
            )
            self.guard.receipt_store.append(receipt)
            self.guard._forget_native_pending_action(
                envelope.metadata.get("openhands_action_id")
            )
            return self.guard.blocked_observation_factory(
                self.tool,
                (
                    f"DualKey blocked '{envelope.tool}' on surface '{envelope.surface}' "
                    f"with decision '{authorization.final_decision}' via rule "
                    f"'{authorization.policy_outcome.rule_id}'."
                ),
            )

        try:
            result = self._call_original_executor(action, conversation)
        except Exception as exc:
            receipt = build_receipt(
                action=envelope,
                authorization=authorization,
                status="tool_error",
                error=str(exc),
                signer=self.guard.signer,
                settings=self.guard.receipt_settings,
            )
            self.guard.receipt_store.append(receipt)
            self.guard._forget_native_pending_action(
                envelope.metadata.get("openhands_action_id")
            )
            raise

        if inspect.isawaitable(result):

            async def finalize() -> Any:
                try:
                    actual = await result
                except Exception as exc:
                    receipt = build_receipt(
                        action=envelope,
                        authorization=authorization,
                        status="tool_error",
                        error=str(exc),
                        signer=self.guard.signer,
                        settings=self.guard.receipt_settings,
                    )
                    self.guard.receipt_store.append(receipt)
                    self.guard._forget_native_pending_action(
                        envelope.metadata.get("openhands_action_id")
                    )
                    raise
                self._append_result_receipt(envelope, authorization, actual)
                return actual

            return finalize()

        self._append_result_receipt(envelope, authorization, result)
        return result

    def _call_original_executor(self, action: Any, conversation: Any | None) -> Any:
        if conversation is not None and self._accepts_conversation:
            return self.original_executor(action, conversation)
        return self.original_executor(action)

    def close(self) -> Any:
        close = getattr(self.original_executor, "close", None)
        if callable(close):
            return close()
        return None

    def _append_result_receipt(
        self,
        action: ActionEnvelope,
        authorization: AuthorizationResult,
        result: Any,
    ) -> None:
        error = _extract_result_error(result)
        receipt = build_receipt(
            action=action,
            authorization=authorization,
            status="tool_error" if error else "executed",
            result=result,
            error=error,
            signer=self.guard.signer,
            settings=self.guard.receipt_settings,
        )
        self.guard.receipt_store.append(receipt)
        self.guard._forget_native_pending_action(
            action.metadata.get("openhands_action_id")
        )


def guard_openhands_tools(
    tools: Any,
    *,
    policy: str | Path | Policy,
    approval_mode: str = "tty",
    approver: ApprovalHandler | None = None,
    receipts_path: str | Path = ".dualkey/openhands-receipts.jsonl",
    receipt_settings: ReceiptSettings | None = None,
    signer: ReceiptSigner | None = None,
    blocked_observation_factory: Callable[[Any, str], Any] | None = None,
) -> Any:
    guard = OpenHandsGuard(
        load_policy(policy),
        approval_mode=approval_mode,
        approver=approver,
        receipt_store=ReceiptStore(receipts_path, settings=receipt_settings),
        receipt_settings=receipt_settings,
        signer=signer,
        blocked_observation_factory=blocked_observation_factory,
    )
    return guard.install_on_tools(tools)


def guard_openhands_agent(
    agent: Any,
    *,
    policy: str | Path | Policy,
    approval_mode: str = "tty",
    approver: ApprovalHandler | None = None,
    receipts_path: str | Path = ".dualkey/openhands-receipts.jsonl",
    receipt_settings: ReceiptSettings | None = None,
    signer: ReceiptSigner | None = None,
    blocked_observation_factory: Callable[[Any, str], Any] | None = None,
) -> Any:
    guard = OpenHandsGuard(
        load_policy(policy),
        approval_mode=approval_mode,
        approver=approver,
        receipt_store=ReceiptStore(receipts_path, settings=receipt_settings),
        receipt_settings=receipt_settings,
        signer=signer,
        blocked_observation_factory=blocked_observation_factory,
    )
    return guard.install_on_agent(agent)


def guard_openhands_conversation(
    conversation: Any,
    *,
    policy: str | Path | Policy,
    approval_mode: str = "tty",
    approver: ApprovalHandler | None = None,
    receipts_path: str | Path = ".dualkey/openhands-receipts.jsonl",
    receipt_settings: ReceiptSettings | None = None,
    signer: ReceiptSigner | None = None,
    blocked_observation_factory: Callable[[Any, str], Any] | None = None,
) -> Any:
    guard = OpenHandsGuard(
        load_policy(policy),
        approval_mode=approval_mode,
        approver=approver,
        receipt_store=ReceiptStore(receipts_path, settings=receipt_settings),
        receipt_settings=receipt_settings,
        signer=signer,
        blocked_observation_factory=blocked_observation_factory,
    )
    return guard.install_on_conversation(conversation)


def _tool_name(tool: Any) -> str:
    return str(getattr(tool, "name", tool.__class__.__name__))


def _tool_title(tool: Any) -> str | None:
    annotations = getattr(tool, "annotations", None)
    return getattr(annotations, "title", None)


def _tool_kind(tool_name: str) -> str:
    normalized = tool_name.lower()
    if normalized in TERMINAL_TOOL_NAMES:
        return "terminal"
    if normalized in FILE_TOOL_NAMES:
        return "file_editor"
    if "git" in normalized:
        return "git"
    return "tool"


def _action_payload(action: Any) -> dict[str, Any]:
    if isinstance(action, Mapping):
        return dict(action)
    if hasattr(action, "model_dump") and callable(action.model_dump):
        return dict(action.model_dump(exclude_none=True))
    if hasattr(action, "dict") and callable(action.dict):
        return dict(action.dict(exclude_none=True))
    return {
        key: value
        for key, value in vars(action).items()
        if not key.startswith("_") and value is not None
    }


def _extract_target(tool_kind: str, payload: Mapping[str, Any]) -> str | None:
    if tool_kind == "terminal":
        command = payload.get("command")
        return str(command) if command else None
    for key in ("path", "repo_path", "target", "branch", "ref", "remote", "url"):
        value = payload.get(key)
        if value is not None:
            return str(value)
    return None


def _derive_surface(tool_kind: str, payload: Mapping[str, Any]) -> str:
    if tool_kind == "terminal":
        return "git" if _git_subcommand(str(payload.get("command", ""))) else "shell"
    if tool_kind == "git":
        return "git"
    return "file" if tool_kind == "file_editor" else "openhands"


def _derive_intent(tool_kind: str, payload: Mapping[str, Any]) -> str:
    if tool_kind == "file_editor":
        command = str(payload.get("command", ""))
        return "read" if command == "view" else "write"
    if tool_kind == "terminal":
        command = str(payload.get("command", ""))
        if payload.get("reset"):
            return "reset"
        git_subcommand = _git_subcommand(command)
        if git_subcommand in READ_ONLY_GIT_SUBCOMMANDS:
            return "read"
        if git_subcommand in WRITE_GIT_SUBCOMMANDS:
            return "write"
        token = _first_shell_token(command)
        if token in READ_ONLY_SHELL_TOKENS:
            return "read"
        return "execute"
    if tool_kind == "git":
        operation = str(
            payload.get("command")
            or payload.get("operation")
            or payload.get("subcommand")
            or ""
        ).lower()
        if operation in READ_ONLY_GIT_SUBCOMMANDS:
            return "read"
        if operation in WRITE_GIT_SUBCOMMANDS:
            return "write"
        return "execute"
    return "invoke"


def _derive_metadata(tool_kind: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    metadata: dict[str, Any] = {}
    if tool_kind == "terminal":
        command = str(payload.get("command", ""))
        metadata["is_input"] = bool(payload.get("is_input"))
        metadata["timeout"] = payload.get("timeout")
        metadata["reset"] = bool(payload.get("reset"))
        metadata["git_subcommand"] = _git_subcommand(command)
        metadata["git_remote"] = _git_remote(command)
        metadata["git_ref"] = _git_ref(command)
    if tool_kind == "file_editor":
        metadata["file_command"] = payload.get("command")
        metadata["view_range"] = payload.get("view_range")
        metadata["insert_line"] = payload.get("insert_line")
    if "summary" in payload:
        metadata["summary"] = payload.get("summary")
    if "security_risk" in payload:
        metadata["security_risk"] = payload.get("security_risk")
    return metadata


def _derive_risk(
    tool_kind: str,
    payload: Mapping[str, Any],
    *,
    target: str | None,
    intent: str,
    surface: str,
) -> set[str]:
    risk: set[str] = set()
    if surface == "shell":
        risk.add("shell")
    if surface == "file":
        risk.add("filesystem")
    if surface == "git":
        risk.add("git")
    if intent in {"read", "write", "execute", "reset"}:
        risk.add(intent)

    path = str(target or "")
    command = str(payload.get("command", ""))
    lowercase_haystacks = [path.lower(), command.lower()]

    if tool_kind == "file_editor" and intent == "write":
        risk.add("write")
    if tool_kind == "terminal":
        if NETWORK_COMMAND_RE.search(command):
            risk.update({"network", "open-world"})
        if DESTRUCTIVE_COMMAND_RE.search(command):
            risk.add("destructive")
        git_subcommand = _git_subcommand(command)
        if git_subcommand in {"push", "pull", "fetch", "clone"}:
            risk.update({"network", "open-world"})
        if git_subcommand in {"reset", "clean", "checkout", "switch", "rebase", "merge"}:
            risk.add("destructive")

    if any(any(marker in haystack for marker in SECRET_MARKERS) for haystack in lowercase_haystacks):
        risk.update({"secrets", "critical-file"})
    if _path_has_git_semantics(path) or surface == "git":
        risk.add("git")

    return risk


def _extract_result_error(result: Any) -> str | None:
    if result is None:
        return None
    if isinstance(result, Mapping):
        error = result.get("error")
        if error:
            return str(error)
        if result.get("is_error"):
            text = result.get("text") or result.get("message")
            return str(text) if text else str(result)
        return None
    if getattr(result, "is_error", False):
        text = getattr(result, "text", None)
        return str(text) if text else str(result)
    return None


def _sanitize_value(value: Any, key: str | None = None) -> Any:
    if isinstance(value, Mapping):
        return {item_key: _sanitize_value(item_value, key=item_key) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [_sanitize_value(item) for item in value]
    if isinstance(value, str):
        lowered_key = (key or "").lower()
        if any(marker in lowered_key for marker in ("token", "secret", "password", "api_key")):
            return "***"
        if len(value) > 500:
            return value[:497] + "..."
    return value


def _git_subcommand(command: str) -> str | None:
    match = re.search(r"(?:^|[;&|]\s*|\s)git\s+([A-Za-z0-9._-]+)", command)
    if match:
        return match.group(1).lower()
    return None


def _git_remote(command: str) -> str | None:
    tokens = _shell_tokens(command)
    if len(tokens) >= 3 and tokens[0] == "git" and tokens[1] == "push":
        return tokens[2]
    return None


def _git_ref(command: str) -> str | None:
    tokens = _shell_tokens(command)
    if len(tokens) >= 4 and tokens[0] == "git" and tokens[1] == "push":
        return tokens[3]
    return None


def _shell_tokens(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def _first_shell_token(command: str) -> str | None:
    tokens = _shell_tokens(command)
    return tokens[0] if tokens else None


def _path_has_git_semantics(path: str) -> bool:
    lowered = path.lower()
    return any(marker in lowered for marker in GIT_PATH_MARKERS)


def _context_from_agent(agent: Any | None) -> dict[str, Any]:
    if agent is None:
        return {}
    return {"agent": agent}


def _context_from_conversation(conversation: Any | None) -> dict[str, Any]:
    if conversation is None:
        return {}
    return {
        "conversation": conversation,
        "agent": getattr(conversation, "agent", None),
        "state": getattr(conversation, "state", None),
        "workspace": getattr(conversation, "workspace", None),
    }


def _session_context(context: Mapping[str, Any] | None) -> tuple[str | None, dict[str, Any]]:
    if not context:
        return None, {}

    conversation = context.get("conversation")
    state = context.get("state")
    agent = context.get("agent")
    workspace = context.get("workspace")

    conversation_id = _normalize_identifier(
        getattr(conversation, "id", None) or getattr(state, "id", None)
    )
    working_dir = _workspace_working_dir(
        workspace or getattr(state, "workspace", None) or getattr(conversation, "workspace", None)
    )
    persistence_dir = getattr(state, "persistence_dir", None)
    metadata = {
        "openhands_conversation_id": conversation_id,
        "openhands_workspace": working_dir,
        "openhands_persistence_dir": str(persistence_dir) if persistence_dir else None,
        "openhands_agent_name": _agent_name(agent),
    }
    return conversation_id, {
        key: value for key, value in metadata.items() if value is not None
    }


def _normalize_status(value: Any) -> str:
    if hasattr(value, "value"):
        value = getattr(value, "value")
    return str(value).lower()


def _lookup_tool(conversation: Any, tool_name: str) -> Any | None:
    try:
        tools_map = conversation.agent.tools_map
    except Exception:
        return None
    return tools_map.get(tool_name)


def _event_action_id(action_event: Any) -> str | None:
    action_id = getattr(action_event, "id", None)
    return str(action_id) if action_id is not None else None


def _event_tool_call_id(action_event: Any) -> str | None:
    tool_call_id = getattr(action_event, "tool_call_id", None)
    return str(tool_call_id) if tool_call_id is not None else None


def _native_correlation_key(tool_name: str, payload: Mapping[str, Any]) -> str:
    return json.dumps(
        {
            "tool": tool_name,
            "payload": _canonicalize_matching_payload(payload),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _openhands_trace_id(
    *,
    tool_name: str,
    payload: Mapping[str, Any],
    tool_call_id: str | None,
    fallback: str | None = None,
) -> str:
    if tool_call_id:
        return f"openhands:{tool_call_id}"
    target = payload.get("path") or payload.get("command") or fallback or tool_name
    return f"openhands:{tool_name}:{target}"


def _native_authorization_result(
    final_decision: str,
    *,
    approved_by: str | None = None,
) -> AuthorizationResult:
    return AuthorizationResult(
        allowed=final_decision == "ask->approved",
        final_decision=final_decision,
        policy_outcome=PolicyOutcome(
            decision="ask",
            rule_id=NATIVE_CONFIRMATION_RULE_ID,
            reason="captured OpenHands native confirmation event",
        ),
        approved_by=approved_by,
        approved_at=utc_now() if approved_by is not None else None,
    )


def _safe_setattr(target: Any, name: str, value: Any) -> None:
    try:
        setattr(target, name, value)
    except Exception:
        object.__setattr__(target, name, value)


def _normalize_identifier(value: Any) -> str | None:
    if value is None:
        return None
    hex_value = getattr(value, "hex", None)
    if isinstance(hex_value, str):
        return hex_value
    if callable(hex_value):
        try:
            normalized = hex_value()
        except Exception:
            normalized = None
        if normalized:
            return str(normalized)
    return str(value)


def _workspace_working_dir(workspace: Any | None) -> str | None:
    if workspace is None:
        return None
    working_dir = getattr(workspace, "working_dir", None)
    if working_dir is None:
        return None
    return str(working_dir)


def _agent_name(agent: Any | None) -> str | None:
    if agent is None:
        return None
    name = getattr(agent, "name", None)
    return str(name) if name else agent.__class__.__name__


def _executor_accepts_conversation(executor: Any) -> bool:
    try:
        signature = inspect.signature(executor)
    except (TypeError, ValueError):
        return True

    positional_params = [
        parameter
        for parameter in signature.parameters.values()
        if parameter.kind in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
    ]
    if len(positional_params) >= 2:
        return True
    return any(
        parameter.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD)
        for parameter in signature.parameters.values()
    )


def _canonicalize_matching_payload(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            key: _canonicalize_matching_payload(item)
            for key, item in _sanitize_value(value).items()
            if key not in {"kind"}
        }
    if isinstance(value, list):
        return [_canonicalize_matching_payload(item) for item in value]
    return value
