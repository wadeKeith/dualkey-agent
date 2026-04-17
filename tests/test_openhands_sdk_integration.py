from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4
from typing import Any

import pytest


pytest.importorskip(
    "openhands.sdk",
    reason="Install dualkey-agent[openhands] on Python 3.12+ to run real OpenHands integration tests.",
)

from openhands.sdk.agent.base import AgentBase
from openhands.sdk.conversation.impl.local_conversation import LocalConversation
from openhands.sdk.conversation.state import ConversationExecutionStatus
from openhands.sdk.event import ActionEvent
from openhands.sdk.llm.message import MessageToolCall, TextContent
from openhands.sdk.tool.schema import Action

from dualkey.openhands_adapter import OpenHandsGuard
from dualkey.policy import Policy
from dualkey.receipts import ReceiptStore


pytestmark = pytest.mark.openhands_integration


class RealObservation:
    def __init__(self, text: str, *, is_error: bool = False) -> None:
        self.text = text
        self.is_error = is_error

    @classmethod
    def from_text(cls, text: str, is_error: bool = False, **_: Any) -> "RealObservation":
        return cls(text, is_error=is_error)

    def __str__(self) -> str:
        return self.text


class RealAction:
    def __init__(self, **payload: Any) -> None:
        self._payload = payload

    def model_dump(self, exclude_none: bool = True) -> dict[str, Any]:
        if not exclude_none:
            return dict(self._payload)
        return {key: value for key, value in self._payload.items() if value is not None}


class RealPendingAction(Action):
    command: str


class RealExecutor:
    def __init__(self, result: RealObservation | None = None) -> None:
        self.result = result or RealObservation("ok")
        self.calls: list[tuple[RealAction, LocalConversation | None]] = []

    def __call__(
        self,
        action: RealAction,
        conversation: LocalConversation | None = None,
    ) -> RealObservation:
        self.calls.append((action, conversation))
        return self.result


class RealTool:
    def __init__(self, name: str, executor: Any, *, title: str | None = None) -> None:
        self.name = name
        self.executor = executor
        self.observation_type = RealObservation
        self.annotations = SimpleNamespace(title=title)

    def set_executor(self, executor: Any) -> "RealTool":
        return RealTool(
            self.name,
            executor,
            title=getattr(self.annotations, "title", None),
        )


class DummyAgent(AgentBase):
    def step(self, *args: Any, **kwargs: Any) -> None:  # pragma: no cover - not used
        raise AssertionError("step() should not run in adapter integration tests")


def _build_agent(tool: RealTool) -> DummyAgent:
    agent = DummyAgent.model_construct(
        llm=None,
        tools=[],
        mcp_config={},
        filter_tools_regex=None,
        include_default_tools=[],
        agent_context=None,
        system_prompt_filename="system_prompt.j2",
        security_policy_filename="security_policy.j2",
        system_prompt_kwargs={},
        condenser=None,
        critic=None,
        tool_concurrency_limit=1,
    )
    agent._tools = {tool.name: tool}
    agent._initialized = True
    return agent


def _pending_action(tool_name: str, command: str, *, tool_call_id: str) -> ActionEvent:
    return ActionEvent(
        thought=[TextContent(text=f"Run {command}")],
        action=RealPendingAction(command=command),
        tool_name=tool_name,
        tool_call_id=tool_call_id,
        tool_call=MessageToolCall(
            id=tool_call_id,
            name=tool_name,
            arguments=f'{{"command":"{command}"}}',
            origin="completion",
        ),
        llm_response_id=str(uuid4()),
    )


def _read_receipts(path: Path) -> list[dict[str, object]]:
    import json

    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_real_local_conversation_waiting_approval_and_execution_align(tmp_path: Path) -> None:
    receipts_path = tmp_path / "openhands-real.jsonl"
    executor = RealExecutor(RealObservation("executed"))
    agent = _build_agent(RealTool("TerminalTool", executor, title="terminal"))
    conversation = LocalConversation(
        agent=agent,
        workspace=tmp_path,
        persistence_dir=tmp_path / "conversation-state",
        visualizer=None,
        delete_on_close=False,
    )

    try:
        conversation.state.events.append(
            _pending_action("TerminalTool", "pytest", tool_call_id="call_real_1")
        )
        guard = OpenHandsGuard(
            Policy.from_mapping({"default_decision": "allow", "rules": []}),
            approval_mode="auto-approve",
            receipt_store=ReceiptStore(receipts_path),
        )
        guard.install_on_conversation(conversation)

        conversation.state.execution_status = (
            ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        )
        conversation.state.execution_status = ConversationExecutionStatus.RUNNING

        result = conversation.agent.tools_map["TerminalTool"].executor(
            RealAction(command="pytest"),
            conversation,
        )

        receipts = _read_receipts(receipts_path)
        assert result.text == "executed"
        assert [receipt["status"] for receipt in receipts] == [
            "openhands_confirmation_waiting",
            "openhands_confirmation_approved",
            "executed",
        ]
        assert receipts[0]["trace_id"] == receipts[1]["trace_id"] == receipts[2]["trace_id"]
        assert receipts[0]["action_hash"] == receipts[1]["action_hash"] == receipts[2]["action_hash"]
        assert executor.calls[0][1] is conversation

        envelope = guard._build_action_envelope(
            conversation.agent.tools_map["TerminalTool"],
            RealAction(command="pytest"),
            context={
                "conversation": conversation,
                "agent": conversation.agent,
                "state": conversation.state,
                "workspace": conversation.workspace,
            },
        )
        assert envelope.session_id == conversation.id.hex
        assert envelope.metadata["openhands_conversation_id"] == conversation.id.hex
        assert envelope.metadata["openhands_workspace"] == str(tmp_path)
    finally:
        conversation.close()


def test_real_local_conversation_rejection_writes_receipt(tmp_path: Path) -> None:
    receipts_path = tmp_path / "openhands-real-reject.jsonl"
    executor = RealExecutor(RealObservation("should not run"))
    agent = _build_agent(RealTool("TerminalTool", executor, title="terminal"))
    conversation = LocalConversation(
        agent=agent,
        workspace=tmp_path,
        persistence_dir=tmp_path / "conversation-state",
        visualizer=None,
        delete_on_close=False,
    )

    try:
        conversation.state.events.append(
            _pending_action(
                "TerminalTool",
                "git push origin main",
                tool_call_id="call_real_2",
            )
        )
        guard = OpenHandsGuard(
            Policy.from_mapping({"default_decision": "allow", "rules": []}),
            approval_mode="auto-approve",
            receipt_store=ReceiptStore(receipts_path),
        )
        guard.install_on_conversation(conversation)

        conversation.state.execution_status = (
            ConversationExecutionStatus.WAITING_FOR_CONFIRMATION
        )
        conversation.reject_pending_actions("Unsafe")

        receipts = _read_receipts(receipts_path)
        assert [receipt["status"] for receipt in receipts] == [
            "openhands_confirmation_waiting",
            "openhands_confirmation_rejected",
        ]
        assert receipts[1]["decision"] == "ask->rejected"
        assert receipts[1]["error"] == "Unsafe"
        assert executor.calls == []
    finally:
        conversation.close()
