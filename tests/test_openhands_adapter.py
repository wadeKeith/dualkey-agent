from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4
from typing import Any

from dualkey.openhands_adapter import (
    OpenHandsGuard,
    guard_openhands_agent,
    guard_openhands_conversation,
    guard_openhands_tools,
)
from dualkey.receipts import ReceiptStore
from dualkey.policy import Policy


class FakeObservation:
    def __init__(self, text: str, *, is_error: bool = False) -> None:
        self._text = text
        self.is_error = is_error

    @classmethod
    def from_text(cls, text: str, is_error: bool = False, **_: Any) -> "FakeObservation":
        return cls(text, is_error=is_error)

    @property
    def text(self) -> str:
        return self._text

    def __str__(self) -> str:
        return self._text


class FakeAction:
    def __init__(self, **payload: Any) -> None:
        self._payload = payload

    def model_dump(self, exclude_none: bool = True) -> dict[str, Any]:
        if not exclude_none:
            return dict(self._payload)
        return {key: value for key, value in self._payload.items() if value is not None}


class FakeExecutor:
    def __init__(self, result: FakeObservation | None = None, *, raises: str | None = None) -> None:
        self.result = result or FakeObservation("ok")
        self.raises = raises
        self.calls: list[tuple[FakeAction, Any | None]] = []

    def __call__(self, action: FakeAction, conversation: Any | None = None) -> FakeObservation:
        self.calls.append((action, conversation))
        if self.raises:
            raise RuntimeError(self.raises)
        return self.result


class FakeTool:
    def __init__(
        self,
        name: str,
        executor: Any,
        *,
        title: str | None = None,
        observation_type: type[FakeObservation] = FakeObservation,
    ) -> None:
        self.name = name
        self.executor = executor
        self.observation_type = observation_type
        self.annotations = SimpleNamespace(title=title)

    def set_executor(self, executor: Any) -> "FakeTool":
        return FakeTool(
            self.name,
            executor,
            title=getattr(self.annotations, "title", None),
            observation_type=self.observation_type,
        )


class FakeAgent:
    def __init__(self, tool_factory: Any) -> None:
        self._tool_factory = tool_factory
        self._tools_map: dict[str, FakeTool] | None = None

    @property
    def tools_map(self) -> dict[str, FakeTool]:
        if self._tools_map is None:
            raise RuntimeError("agent not initialized")
        return self._tools_map

    def init_state(self) -> str:
        self._tools_map = self._tool_factory()
        return "initialized"


class FakeStateUpdateEvent:
    def __init__(self, key: str, value: Any) -> None:
        self.key = key
        self.value = value


class FakeActionEvent:
    def __init__(self, tool_name: str, action: FakeAction, *, tool_call_id: str) -> None:
        self.id = str(uuid4())
        self.tool_name = tool_name
        self.tool_call_id = tool_call_id
        self.action = action


class FakeUserRejectObservation:
    def __init__(self, action_id: str, tool_name: str, tool_call_id: str, rejection_reason: str) -> None:
        self.action_id = action_id
        self.tool_name = tool_name
        self.tool_call_id = tool_call_id
        self.rejection_reason = rejection_reason


class FakeConversationState:
    def __init__(self, events: list[Any]) -> None:
        self.id = uuid4()
        self.events = events
        self.workspace = SimpleNamespace(working_dir="/tmp/dualkey-openhands-workspace")
        self.persistence_dir = "/tmp/dualkey-openhands-persistence"
        self._execution_status = "idle"
        self._on_state_change = None

    @property
    def execution_status(self) -> str:
        return self._execution_status

    @execution_status.setter
    def execution_status(self, value: str) -> None:
        old = self._execution_status
        self._execution_status = value
        if old != value and self._on_state_change is not None:
            self._on_state_change(FakeStateUpdateEvent("execution_status", value))

    def set_on_state_change(self, callback: Any) -> None:
        self._on_state_change = callback

    @staticmethod
    def get_unmatched_actions(events: list[Any]) -> list[FakeActionEvent]:
        observed_action_ids = {
            event.action_id
            for event in events
            if hasattr(event, "action_id")
        }
        return [
            event
            for event in events
            if isinstance(event, FakeActionEvent) and event.id not in observed_action_ids
        ]


class FakeConversation:
    def __init__(self, agent: FakeAgent, state: FakeConversationState) -> None:
        self.id = uuid4()
        self.agent = agent
        self.state = state
        self.workspace = state.workspace

    def reject_pending_actions(self, reason: str = "User rejected the action") -> None:
        pending_actions = self.state.get_unmatched_actions(self.state.events)
        if self.state.execution_status == "waiting_for_confirmation":
            self.state.execution_status = "idle"
        for action_event in pending_actions:
            self.state.events.append(
                FakeUserRejectObservation(
                    action_id=action_event.id,
                    tool_name=action_event.tool_name,
                    tool_call_id=action_event.tool_call_id,
                    rejection_reason=reason,
                )
            )

    def run(self) -> None:
        if self.state.execution_status == "waiting_for_confirmation":
            self.state.execution_status = "running"


def read_receipts(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_openhands_agent_wraps_tools_after_init_and_blocks_destructive_shell(tmp_path: Path) -> None:
    receipts_path = tmp_path / "openhands.jsonl"
    terminal_executor = FakeExecutor(FakeObservation("should not run"))
    agent = FakeAgent(
        lambda: {
            "TerminalTool": FakeTool("TerminalTool", terminal_executor, title="terminal"),
        }
    )
    policy = Policy.from_mapping(
        {
            "default_decision": "allow",
            "rules": [
                {
                    "id": "deny_rm_rf",
                    "decision": "deny",
                    "when": {
                        "actor": "openhands",
                        "tool_glob": "*TerminalTool",
                        "arg_regex": {"command": r"(^|[;&|]\s*|\s)rm\s+-rf\b"},
                    },
                }
            ],
        }
    )

    guard_openhands_agent(
        agent,
        policy=policy,
        approval_mode="auto-deny",
        receipts_path=receipts_path,
    )
    assert agent.init_state() == "initialized"

    result = agent.tools_map["TerminalTool"].executor(FakeAction(command="rm -rf /repo"))

    assert result.is_error is True
    assert "DualKey blocked" in result.text
    assert terminal_executor.calls == []
    receipt = read_receipts(receipts_path)[0]
    assert receipt["decision"] == "deny"
    assert receipt["status"] == "blocked"


def test_openhands_wraps_git_push_and_auto_approves(tmp_path: Path) -> None:
    receipts_path = tmp_path / "openhands.jsonl"
    terminal_executor = FakeExecutor(FakeObservation("pushed successfully"))
    tools_map = {
        "TerminalTool": FakeTool("TerminalTool", terminal_executor, title="terminal"),
    }
    policy = Policy.from_mapping(
        {
            "default_decision": "allow",
            "rules": [
                {
                    "id": "push_main_requires_second_key",
                    "decision": "ask",
                    "when": {
                        "actor": "openhands",
                        "surface": "git",
                        "arg_regex": {
                            "command": r"(^|[;&|]\s*|\s)git\s+push\s+\S+\s+main(\s|$)",
                        },
                    },
                }
            ],
        }
    )

    guard_openhands_tools(
        tools_map,
        policy=policy,
        approval_mode="auto-approve",
        receipts_path=receipts_path,
    )

    result = tools_map["TerminalTool"].executor(FakeAction(command="git push origin main"))

    assert result.text == "pushed successfully"
    assert len(terminal_executor.calls) == 1
    assert terminal_executor.calls[0][0].model_dump() == {"command": "git push origin main"}
    assert terminal_executor.calls[0][1] is None
    receipt = read_receipts(receipts_path)[0]
    assert receipt["decision"] == "ask->approved"
    assert receipt["status"] == "executed"
    assert receipt["approved_by"] == "dualkey:auto"


def test_openhands_file_editor_denies_secret_write(tmp_path: Path) -> None:
    receipts_path = tmp_path / "openhands.jsonl"
    file_executor = FakeExecutor(FakeObservation("should not run"))
    tools_map = {
        "FileEditorTool": FakeTool("FileEditorTool", file_executor, title="file_editor"),
    }
    policy = Policy.from_mapping(
        {
            "default_decision": "allow",
            "rules": [
                {
                    "id": "deny_secret_write",
                    "decision": "deny",
                    "when": {
                        "actor": "openhands",
                        "tool_glob": "*FileEditorTool",
                        "target_glob": "*.env",
                    },
                }
            ],
        }
    )

    guard_openhands_tools(
        tools_map,
        policy=policy,
        approval_mode="auto-deny",
        receipts_path=receipts_path,
    )

    result = tools_map["FileEditorTool"].executor(
        FakeAction(command="create", path="/repo/.env", file_text="TOKEN=secret")
    )

    assert result.is_error is True
    assert file_executor.calls == []
    receipt = read_receipts(receipts_path)[0]
    assert receipt["decision"] == "deny"
    assert receipt["status"] == "blocked"


def test_openhands_executor_error_is_receipted(tmp_path: Path) -> None:
    receipts_path = tmp_path / "openhands.jsonl"
    terminal_executor = FakeExecutor(raises="terminal crashed")
    tools_map = {
        "TerminalTool": FakeTool("TerminalTool", terminal_executor, title="terminal"),
    }

    guard_openhands_tools(
        tools_map,
        policy=Policy.from_mapping({"default_decision": "allow", "rules": []}),
        approval_mode="auto-approve",
        receipts_path=receipts_path,
    )

    try:
        tools_map["TerminalTool"].executor(FakeAction(command="pytest"))
    except RuntimeError as exc:
        assert str(exc) == "terminal crashed"
    else:
        raise AssertionError("expected wrapped OpenHands executor to re-raise tool error")

    receipt = read_receipts(receipts_path)[0]
    assert receipt["status"] == "tool_error"
    assert receipt["error"] == "terminal crashed"


def test_openhands_native_confirmation_waiting_and_approval_align_with_execution(tmp_path: Path) -> None:
    receipts_path = tmp_path / "openhands.jsonl"
    terminal_executor = FakeExecutor(FakeObservation("Executed: pytest"))
    agent = FakeAgent(
        lambda: {
            "TerminalTool": FakeTool("TerminalTool", terminal_executor, title="terminal"),
        }
    )
    agent.init_state()
    pending_action = FakeActionEvent(
        "TerminalTool",
        FakeAction(command="pytest"),
        tool_call_id="call_pending_1",
    )
    conversation = FakeConversation(agent, FakeConversationState([pending_action]))

    guard_openhands_conversation(
        conversation,
        policy=Policy.from_mapping({"default_decision": "allow", "rules": []}),
        approval_mode="auto-approve",
        receipts_path=receipts_path,
    )

    conversation.state.execution_status = "waiting_for_confirmation"
    conversation.run()
    result = conversation.agent.tools_map["TerminalTool"].executor(FakeAction(command="pytest"))

    assert result.text == "Executed: pytest"
    receipts = read_receipts(receipts_path)
    assert [receipt["status"] for receipt in receipts] == [
        "openhands_confirmation_waiting",
        "openhands_confirmation_approved",
        "executed",
    ]
    assert receipts[0]["decision"] == "ask"
    assert receipts[1]["decision"] == "ask->approved"
    assert receipts[2]["decision"] == "allow"
    assert receipts[0]["trace_id"] == "openhands:call_pending_1"
    assert receipts[0]["trace_id"] == receipts[1]["trace_id"] == receipts[2]["trace_id"]
    assert receipts[0]["action_hash"] == receipts[1]["action_hash"] == receipts[2]["action_hash"]
    assert len(terminal_executor.calls) == 1
    assert terminal_executor.calls[0][0].model_dump() == {"command": "pytest"}
    assert terminal_executor.calls[0][1] is None


def test_openhands_conversation_receipts_include_real_session_metadata(tmp_path: Path) -> None:
    receipts_path = tmp_path / "openhands.jsonl"
    terminal_executor = FakeExecutor(FakeObservation("ok"))
    agent = FakeAgent(
        lambda: {
            "TerminalTool": FakeTool("TerminalTool", terminal_executor, title="terminal"),
        }
    )
    agent.init_state()
    pending_action = FakeActionEvent(
        "TerminalTool",
        FakeAction(command="pytest"),
        tool_call_id="call_pending_metadata",
    )
    conversation = FakeConversation(agent, FakeConversationState([pending_action]))

    guard = OpenHandsGuard(
        Policy.from_mapping({"default_decision": "allow", "rules": []}),
        approval_mode="auto-approve",
        receipt_store=ReceiptStore(receipts_path),
    )
    guard.install_on_conversation(conversation)

    conversation.state.execution_status = "waiting_for_confirmation"
    conversation.state.execution_status = "running"
    conversation.agent.tools_map["TerminalTool"].executor(FakeAction(command="pytest"))

    receipts = read_receipts(receipts_path)
    assert {receipt["trace_id"] for receipt in receipts} == {"openhands:call_pending_metadata"}
    assert receipts[0]["action_hash"] == receipts[1]["action_hash"] == receipts[2]["action_hash"]

    envelope = guard._build_action_envelope(
        conversation.agent.tools_map["TerminalTool"],
        FakeAction(command="pytest"),
        context={
            "conversation": conversation,
            "agent": conversation.agent,
            "state": conversation.state,
            "workspace": conversation.workspace,
        },
    )
    assert envelope.session_id == conversation.id.hex
    assert envelope.metadata["openhands_conversation_id"] == conversation.id.hex
    assert envelope.metadata["openhands_workspace"] == "/tmp/dualkey-openhands-workspace"
    assert envelope.metadata["openhands_persistence_dir"] == "/tmp/dualkey-openhands-persistence"


def test_openhands_native_confirmation_rejection_writes_receipt(tmp_path: Path) -> None:
    receipts_path = tmp_path / "openhands.jsonl"
    terminal_executor = FakeExecutor(FakeObservation("should not run"))
    agent = FakeAgent(
        lambda: {
            "TerminalTool": FakeTool("TerminalTool", terminal_executor, title="terminal"),
        }
    )
    agent.init_state()
    pending_action = FakeActionEvent(
        "TerminalTool",
        FakeAction(command="git push origin main"),
        tool_call_id="call_pending_2",
    )
    conversation = FakeConversation(agent, FakeConversationState([pending_action]))

    guard_openhands_conversation(
        conversation,
        policy=Policy.from_mapping({"default_decision": "allow", "rules": []}),
        approval_mode="auto-approve",
        receipts_path=receipts_path,
    )

    conversation.state.execution_status = "waiting_for_confirmation"
    conversation.reject_pending_actions("Not safe to run")

    receipts = read_receipts(receipts_path)
    assert [receipt["status"] for receipt in receipts] == [
        "openhands_confirmation_waiting",
        "openhands_confirmation_rejected",
    ]
    assert receipts[1]["decision"] == "ask->rejected"
    assert receipts[1]["error"] == "Not safe to run"
    assert receipts[0]["trace_id"] == receipts[1]["trace_id"] == "openhands:call_pending_2"
    assert terminal_executor.calls == []
