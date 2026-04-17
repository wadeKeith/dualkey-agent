# OpenHands Adapter

`guard_openhands_agent()`, `guard_openhands_tools()`, and `guard_openhands_conversation()` connect DualKey to the OpenHands SDK. Instead of replacing OpenHands planning or its native confirmation system, DualKey wraps each resolved `ToolExecutor.__call__()` and runs the same `ActionEnvelope -> policy -> approval -> receipt` flow already used by the MCP proxy, Claude Code hook, and browser-use adapter.

## Why this boundary

OpenHands documents the tool system as `Action -> Observation`, with `ToolExecutor` implementing the execution logic and `ToolDefinition` binding schemas to executors. `TerminalTool` and `FileEditorTool` are the concrete coding surfaces for shell and file operations, and the public `Agent.tools_map` exposes the initialized tool definitions.

That makes the executor boundary the narrowest stable place to add:

- deterministic allow / ask / deny policy
- second-key approvals for shell, file, and git actions
- signed receipts for blocked, executed, and errored tool calls

## Minimal setup

```python
from pydantic import SecretStr

from openhands.sdk import Agent, Conversation, LLM, Tool
from dualkey import guard_openhands_conversation

llm = LLM(
    model="anthropic/claude-sonnet-4-5-20250929",
    api_key=SecretStr("..."),
)

agent = Agent(
    llm=llm,
    tools=[
        Tool(name="TerminalTool"),
        Tool(name="FileEditorTool"),
    ],
)

conversation = Conversation(agent=agent, workspace=".")
guard_openhands_conversation(
    conversation,
    policy="policy/examples/openhands.yaml",
    approval_mode="tty",
)
conversation.send_message("fix the bug, commit the change, and push main")
conversation.run()
```

If you only need executor-level protection, you can wrap the agent or the resolved tools directly:

```python
from dualkey import guard_openhands_agent, guard_openhands_tools

guard_openhands_agent(
    agent,
    policy="policy/examples/openhands.yaml",
    approval_mode="tty",
)

guard_openhands_tools(
    agent.tools_map,
    policy="policy/examples/openhands.yaml",
    approval_mode="auto-approve",
)
```

## What DualKey extracts

For `TerminalTool` / `BashTool`, the adapter reads the action payload and classifies:

- `surface=shell` for regular commands
- `surface=git` when the command is a git operation
- `intent=read` for commands like `git diff` or `ls`
- `intent=write` for commands like `git push`, `git commit`, or `git reset`

For `FileEditorTool`, the adapter maps:

- `command=view` -> `surface=file`, `intent=read`
- `command=create|str_replace|insert|undo_edit` -> `surface=file`, `intent=write`
- secret or critical paths like `.env` and `.ssh` -> extra risk tags

Each action becomes a normalized envelope with tool metadata, git subcommand hints, sanitized arguments, and risk tags such as `shell`, `filesystem`, `git`, `destructive`, `network`, `secrets`, and `critical-file`.

## Relationship to native OpenHands confirmation

OpenHands already exposes `confirmation_policy` and `security_analyzer` as first-class SDK features. DualKey does not replace those mechanisms. It adds an external deterministic matcher and signed receipt layer at the executor boundary.

In practice:

- use native OpenHands confirmation when you want the agent loop to pause on model-assessed risk
- use DualKey when you want explicit path / regex / tool / metadata rules that are auditable and shared with other runtimes

If you use `guard_openhands_conversation()`, DualKey also patches the conversation's state-change callback and `reject_pending_actions()` flow so native confirmation events land in the same receipt stream.

## Two layers of evidence

With `guard_openhands_conversation()`, a single risky action can now produce aligned receipts at two levels:

- conversation-level: `openhands_confirmation_waiting`
- conversation-level: `openhands_confirmation_approved` or `openhands_confirmation_rejected`
- executor-level: `executed`, `blocked`, or `tool_error`

DualKey aligns these receipts through the same normalized `ActionEnvelope`, which means the native confirmation receipts and the executor receipt share the same `trace_id`. When the underlying action payload is the same, they also share the same `action_hash`, so you can correlate:

- the moment OpenHands paused the loop
- the human or policy approval / rejection outcome
- the final tool execution or block result

This keeps conversation-level waiting / reject evidence and executor-level block / approve evidence tied to one auditable action record instead of two unrelated logs.

When DualKey has a real `LocalConversation`, it also derives session metadata from that object instead of falling back to a synthetic placeholder. That means OpenHands envelopes can carry:

- `session_id=<conversation.id.hex>`
- `metadata.openhands_conversation_id`
- `metadata.openhands_workspace`
- `metadata.openhands_persistence_dir`
- `metadata.openhands_agent_name`

This improves replay, audit filtering, and cross-receipt correlation in multi-conversation runs.

## Real SDK tests

The repo now includes optional integration tests that use the real `openhands-sdk` `LocalConversation`, `ConversationState`, and `ActionEvent` types.

Install the optional dependency set and run the OpenHands integration tests:

```bash
python3 -m pip install -e '.[openhands]'
python3 -m pytest -q tests/test_openhands_sdk_integration.py
```

Because upstream `openhands-sdk` currently requires Python 3.12+, this compatibility path is pinned to Python 3.12 in CI even though the core DualKey package still supports Python 3.11+.

These tests verify:

- native `waiting_for_confirmation` -> `running` state transitions produce aligned receipts
- `reject_pending_actions()` produces a rejection receipt in the same stream
- executor calls still line up with the native confirmation receipts through the same `trace_id` and `action_hash`
- conversation id and workspace metadata are pulled from the real OpenHands objects

CI now runs this real OpenHands job separately from the base unit-test matrix so SDK compatibility regressions show up even when the pure-Python test suite still passes.

By default, OpenHands receipts still go to `.dualkey/openhands-receipts.jsonl`. If you want indexed audit queries instead, pass a `receipts_path` ending in `.sqlite`, `.sqlite3`, or `.db`.

## Starter policy

The included [policy/examples/openhands.yaml](../policy/examples/openhands.yaml) demonstrates:

- automatic allow for read-only git actions
- deny for secret file writes
- deny for destructive shell commands
- second-key approval for `git push ... main`
- second-key approval for non-view file edits
