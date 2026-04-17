from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
import json
from pathlib import Path
import sys
from typing import Any
import uuid

from dualkey.approvals import ConsoleApprover
from dualkey.models import ActionEnvelope, ApprovalDecision, AuthorizationResult
from dualkey.policy import Policy, load_policy
from dualkey.receipts import (
    ReceiptSettings,
    ReceiptSigner,
    ReceiptStore,
    add_receipt_settings_arguments,
    build_receipt,
    receipt_settings_from_args,
)


JsonObject = dict[str, Any]

SECRET_FIELDS = {
    "api_key",
    "apikey",
    "authorization",
    "password",
    "secret",
    "secret_key",
    "token",
}
TARGET_KEYS = (
    "path",
    "file_path",
    "target",
    "url",
    "uri",
    "command",
    "branch",
    "selector",
    "recipient",
    "to",
    "query",
)


@dataclass(slots=True)
class PendingRequest:
    method: str
    action: ActionEnvelope | None = None
    authorization: AuthorizationResult | None = None


class MCPProxy:
    def __init__(
        self,
        *,
        policy: Policy,
        downstream_command: list[str],
        approval_mode: str = "auto",
        receipt_store: ReceiptStore | None = None,
        receipt_settings: ReceiptSettings | None = None,
        signer: ReceiptSigner | None = None,
    ) -> None:
        if not downstream_command:
            raise ValueError("downstream_command must not be empty")

        self.policy = policy
        self.downstream_command = downstream_command
        self.approval_mode = approval_mode
        self.receipt_settings = receipt_settings or getattr(receipt_store, "settings", None) or ReceiptSettings.from_env()
        self.receipt_store = receipt_store or ReceiptStore(
            ".dualkey/mcp-proxy-receipts.jsonl",
            settings=self.receipt_settings,
        )
        if receipt_store is not None and hasattr(self.receipt_store, "settings"):
            self.receipt_store.settings = self.receipt_settings
        self.signer = signer or ReceiptSigner()

        self.proxy_run_id = uuid.uuid4().hex
        self.session_id = f"mcp-proxy:{self.proxy_run_id}"
        self.client_info: dict[str, Any] = {}
        self.client_protocol_version: str | None = None
        self.server_protocol_version: str | None = None
        self.client_capabilities: dict[str, Any] = {}
        self.server_info: dict[str, Any] = {}
        self.tool_registry: dict[str, JsonObject] = {}
        self.pending_downstream_requests: dict[str | int, PendingRequest] = {}
        self.pending_client_requests: dict[str | int, asyncio.Future[JsonObject]] = {}
        self.client_write_lock = asyncio.Lock()
        self.server_write_lock = asyncio.Lock()
        self.background_tasks: set[asyncio.Task[Any]] = set()
        self.proxy_request_counter = 0
        self.process: asyncio.subprocess.Process | None = None

    async def run(self) -> int:
        self.process = await asyncio.create_subprocess_exec(
            *self.downstream_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        client_task = asyncio.create_task(self._pump_client_to_server(), name="dualkey-client-pump")
        server_task = asyncio.create_task(self._pump_server_to_client(), name="dualkey-server-pump")
        stderr_task = asyncio.create_task(self._pump_server_stderr(), name="dualkey-stderr-pump")

        done, pending = await asyncio.wait(
            {client_task, server_task, stderr_task},
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in pending:
            task.cancel()
        for task in self.background_tasks:
            task.cancel()

        await asyncio.gather(*pending, return_exceptions=True)
        await asyncio.gather(*self.background_tasks, return_exceptions=True)

        if self.process.returncode is None:
            self.process.terminate()
            await self.process.wait()
        return int(self.process.returncode or 0)

    async def _pump_client_to_server(self) -> None:
        while True:
            raw = await asyncio.to_thread(sys.stdin.buffer.readline)
            if not raw:
                if self.process and self.process.stdin:
                    self.process.stdin.close()
                return

            for message in self._decode_messages(raw):
                task = asyncio.create_task(self._handle_client_message(message))
                self.background_tasks.add(task)
                task.add_done_callback(self.background_tasks.discard)

    async def _pump_server_to_client(self) -> None:
        assert self.process is not None
        assert self.process.stdout is not None

        while True:
            raw = await self.process.stdout.readline()
            if not raw:
                return

            for message in self._decode_messages(raw):
                await self._handle_server_message(message)

    async def _pump_server_stderr(self) -> None:
        assert self.process is not None
        assert self.process.stderr is not None

        while True:
            raw = await self.process.stderr.readline()
            if not raw:
                return
            sys.stderr.buffer.write(raw)
            sys.stderr.buffer.flush()

    def _decode_messages(self, raw: bytes) -> list[JsonObject]:
        text = raw.decode("utf-8").strip()
        if not text:
            return []
        payload = json.loads(text)
        if isinstance(payload, list):
            return payload
        return [payload]

    async def _handle_client_message(self, message: JsonObject) -> None:
        if self._is_response(message):
            message_id = message.get("id")
            future = self.pending_client_requests.pop(message_id, None)
            if future is not None and not future.done():
                future.set_result(message)
                return
            await self._send_to_server(message)
            return

        if message.get("method") == "initialize":
            self.client_capabilities = dict(message.get("params", {}).get("capabilities", {}))
            self.client_info = dict(message.get("params", {}).get("clientInfo", {}))
            protocol_version = message.get("params", {}).get("protocolVersion")
            self.client_protocol_version = str(protocol_version) if protocol_version is not None else None
            if "id" in message:
                self.pending_downstream_requests[message["id"]] = PendingRequest(method="initialize")
            await self._send_to_server(message)
            return

        if message.get("method") == "tools/list" and "id" in message:
            self.pending_downstream_requests[message["id"]] = PendingRequest(method="tools/list")
            await self._send_to_server(message)
            return

        if message.get("method") == "tools/call":
            await self._handle_tool_call(message)
            return

        await self._send_to_server(message)

    async def _handle_server_message(self, message: JsonObject) -> None:
        if self._is_response(message):
            request = self.pending_downstream_requests.pop(message.get("id"), None)
            if request is not None:
                if request.method == "initialize":
                    self.server_info = dict(message.get("result", {}).get("serverInfo", {}))
                    protocol_version = message.get("result", {}).get("protocolVersion")
                    self.server_protocol_version = (
                        str(protocol_version) if protocol_version is not None else None
                    )
                elif request.method == "tools/list":
                    self._cache_tools(message.get("result", {}).get("tools", []))
                elif request.method == "tools/call" and request.action and request.authorization:
                    self._record_tool_completion(
                        action=request.action,
                        authorization=request.authorization,
                        response=message,
                    )
        elif message.get("method") == "notifications/tools/list_changed":
            self.tool_registry.clear()

        await self._send_to_client(message)

    async def _handle_tool_call(self, message: JsonObject) -> None:
        request_id = message.get("id")
        params = dict(message.get("params", {}))
        tool_name = str(params.get("name", "unknown"))
        arguments = dict(params.get("arguments", {}))
        tool_def = self.tool_registry.get(tool_name, {})
        action = self._build_action_envelope(tool_name=tool_name, arguments=arguments, tool_def=tool_def, request_id=request_id)
        outcome = self.policy.evaluate(action)

        if outcome.decision == "deny":
            authorization = AuthorizationResult(
                allowed=False,
                final_decision="deny",
                policy_outcome=outcome,
            )
            await self._respond_with_blocked_tool_result(request_id=request_id, action=action, authorization=authorization)
            return

        if outcome.decision == "ask":
            approval = await self._request_second_key(action=action, rule_id=outcome.rule_id)
            authorization = AuthorizationResult(
                allowed=approval.approved,
                final_decision="ask->approved" if approval.approved else "ask->rejected",
                policy_outcome=outcome,
                approved_by=approval.approver,
                approval_note=approval.note,
                approved_at=approval.approved_at,
            )
            if not approval.approved:
                await self._respond_with_blocked_tool_result(request_id=request_id, action=action, authorization=authorization)
                return
        else:
            authorization = AuthorizationResult(
                allowed=True,
                final_decision="allow",
                policy_outcome=outcome,
            )

        if request_id is not None:
            self.pending_downstream_requests[request_id] = PendingRequest(
                method="tools/call",
                action=action,
                authorization=authorization,
            )
        await self._send_to_server(message)

    async def _request_second_key(self, *, action: ActionEnvelope, rule_id: str) -> ApprovalDecision:
        if self.approval_mode == "auto-approve":
            return ApprovalDecision(approved=True, approver="dualkey:auto", note="auto-approved by proxy")
        if self.approval_mode == "auto-deny":
            return ApprovalDecision(approved=False, approver="dualkey:auto", note="auto-denied by proxy")

        if self.approval_mode in {"auto", "elicitation"} and self._supports_form_elicitation():
            return await self._request_second_key_via_elicitation(action=action, rule_id=rule_id)

        if self.approval_mode in {"auto", "tty"}:
            tty_streams = self._open_tty_streams()
            if tty_streams is not None:
                stdin, stdout = tty_streams
                approver = ConsoleApprover(
                    auto_approve=False,
                    identity="human:tty",
                    stdin=stdin,
                    stdout=stdout,
                )
                return approver.review(action, self.policy.evaluate(action))

        return ApprovalDecision(
            approved=False,
            approver="dualkey:unavailable",
            note="no approval surface was available for this request",
        )

    async def _request_second_key_via_elicitation(self, *, action: ActionEnvelope, rule_id: str) -> ApprovalDecision:
        proxy_request_id = self._next_proxy_request_id()
        future: asyncio.Future[JsonObject] = asyncio.get_running_loop().create_future()
        self.pending_client_requests[proxy_request_id] = future

        preview_lines = action.preview()
        message = {
            "jsonrpc": "2.0",
            "id": proxy_request_id,
            "method": "elicitation/create",
            "params": {
                "mode": "form",
                "message": (
                    "DualKey approval required before executing an MCP tool.\n\n"
                    + "\n".join(preview_lines[:6])
                    + f"\npolicy_match: {rule_id}"
                ),
                "requestedSchema": {
                    "type": "object",
                    "properties": {
                        "decision": {
                            "type": "string",
                            "title": "Decision",
                            "description": "Choose whether to let this tool call run.",
                            "enum": ["approve", "reject"],
                            "default": "reject",
                        },
                        "note": {
                            "type": "string",
                            "title": "Note",
                            "description": "Optional note to store with the approval receipt.",
                        },
                    },
                    "required": ["decision"],
                },
            },
        }
        await self._send_to_client(message)
        response = await future
        result = dict(response.get("result", {}))
        content = dict(result.get("content", {}))
        approved = result.get("action") == "accept" and content.get("decision") == "approve"
        return ApprovalDecision(
            approved=approved,
            approver="human:elicitation",
            note=content.get("note") or result.get("action", "cancel"),
        )

    async def _respond_with_blocked_tool_result(
        self,
        *,
        request_id: str | int | None,
        action: ActionEnvelope,
        authorization: AuthorizationResult,
    ) -> None:
        receipt = build_receipt(
            action=action,
            authorization=authorization,
            status="blocked",
            error=f"blocked by {authorization.policy_outcome.rule_id}",
            signer=self.signer,
            settings=self.receipt_settings,
        )
        self.receipt_store.append(receipt)

        if request_id is None:
            return

        response = {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": (
                            f"DualKey blocked '{action.tool}' with decision "
                            f"'{authorization.final_decision}' via rule '{authorization.policy_outcome.rule_id}'."
                        ),
                    }
                ],
                "structuredContent": {
                    "dualkey": {
                        "decision": authorization.final_decision,
                        "policy_match": authorization.policy_outcome.rule_id,
                        "action_hash": action.fingerprint(),
                    }
                },
                "isError": True,
            },
        }
        await self._send_to_client(response)

    def _record_tool_completion(
        self,
        *,
        action: ActionEnvelope,
        authorization: AuthorizationResult,
        response: JsonObject,
    ) -> None:
        status = "executed"
        error = None
        result_preview: Any = response.get("result")

        if "error" in response:
            status = "protocol_error"
            error = str(response["error"])
            result_preview = None
        elif response.get("result", {}).get("isError") is True:
            status = "tool_error"

        receipt = build_receipt(
            action=action,
            authorization=authorization,
            status=status,
            result=result_preview,
            error=error,
            signer=self.signer,
            settings=self.receipt_settings,
        )
        self.receipt_store.append(receipt)

    def _cache_tools(self, tools: list[JsonObject]) -> None:
        for tool in tools:
            name = tool.get("name")
            if isinstance(name, str):
                self.tool_registry[name] = dict(tool)

    def _build_action_envelope(
        self,
        *,
        tool_name: str,
        arguments: JsonObject,
        tool_def: JsonObject,
        request_id: str | int | None,
    ) -> ActionEnvelope:
        sanitized_args = self._sanitize_args(arguments)
        target = self._extract_target(arguments)
        risk = self._derive_risk(tool_name=tool_name, arguments=arguments, tool_def=tool_def, target=target)
        intent = self._derive_intent(tool_name=tool_name, tool_def=tool_def, arguments=arguments)
        session_id = self._current_session_id()

        actor = self.server_info.get("name") or "mcp-server"
        return ActionEnvelope(
            actor=str(actor),
            surface="mcp",
            tool=tool_name,
            intent=intent,
            target=target,
            args=sanitized_args,
            risk=risk,
            session_id=session_id,
            trace_id=f"{session_id}:{request_id if request_id is not None else uuid.uuid4()}",
            metadata={
                "mcp_proxy_run_id": self.proxy_run_id,
                "mcp_client_info": self.client_info,
                "mcp_client_protocol_version": self.client_protocol_version,
                "mcp_server_info": self.server_info,
                "mcp_server_protocol_version": self.server_protocol_version,
                "mcp_tool_annotations": tool_def.get("annotations", {}),
                "mcp_tool_description": tool_def.get("description"),
                "mcp_tool_input_schema": tool_def.get("inputSchema"),
                "mcp_request_id": None if request_id is None else str(request_id),
                "mcp_downstream_command": list(self.downstream_command),
            },
        )

    def _derive_intent(self, *, tool_name: str, tool_def: JsonObject, arguments: JsonObject) -> str:
        annotations = dict(tool_def.get("annotations", {}))
        normalized = f"{tool_name} {tool_def.get('description', '')}".lower()

        if annotations.get("readOnlyHint") is True:
            return "read"
        if "command" in arguments or any(token in normalized for token in ("shell", "bash", "exec", "run")):
            return "execute"
        if "click" in normalized:
            return "click"
        if any(token in normalized for token in ("email", "mail", "send")):
            return "send"
        if any(token in normalized for token in ("read", "get", "list", "search", "query", "fetch")):
            return "read"
        if any(token in normalized for token in ("write", "edit", "update", "create", "delete", "remove", "push")):
            return "write"
        return "invoke"

    def _derive_risk(
        self,
        *,
        tool_name: str,
        arguments: JsonObject,
        tool_def: JsonObject,
        target: str | None,
    ) -> list[str]:
        annotations = dict(tool_def.get("annotations", {}))
        description = str(tool_def.get("description", "")).lower()
        normalized = f"{tool_name} {description}".lower()
        risk: set[str] = set()

        if annotations.get("readOnlyHint") is True:
            risk.add("read-only")
        if annotations.get("destructiveHint") is True:
            risk.add("destructive")
        if annotations.get("openWorldHint") is True:
            risk.add("open-world")
        if annotations.get("idempotentHint") is True:
            risk.add("idempotent")

        for key, value in arguments.items():
            key_lower = key.lower()
            if any(secret_key in key_lower for secret_key in SECRET_FIELDS):
                risk.add("secrets")
            if isinstance(value, str):
                lowered = value.lower()
                if any(marker in lowered for marker in (".env", "/.ssh/", "id_rsa", "secret", "token", "api_key")):
                    risk.add("secrets")
                    risk.add("critical-file")
                if "git push" in lowered:
                    risk.add("git")
                    risk.add("network")
                if "rm -rf" in lowered:
                    risk.add("destructive")
                if any(marker in lowered for marker in ("pay", "checkout", "purchase")):
                    risk.add("payment")

        if target:
            lowered_target = target.lower()
            if any(marker in lowered_target for marker in ("pay", "checkout", "purchase")):
                risk.add("payment")
            if any(marker in lowered_target for marker in (".env", "/.ssh/", "id_rsa")):
                risk.add("secrets")
                risk.add("critical-file")

        if any(marker in normalized for marker in ("browser", "click", "navigate")):
            risk.add("browser")
        if any(marker in normalized for marker in ("payment", "checkout", "pay")):
            risk.add("payment")
        return sorted(risk)

    def _extract_target(self, arguments: JsonObject) -> str | None:
        for key in TARGET_KEYS:
            value = arguments.get(key)
            if isinstance(value, str) and value:
                return value
        return None

    def _sanitize_args(self, value: Any, *, key: str | None = None) -> Any:
        if isinstance(value, dict):
            return {item_key: self._sanitize_args(item_value, key=item_key) for item_key, item_value in value.items()}
        if isinstance(value, list):
            return [self._sanitize_args(item) for item in value]
        if isinstance(value, str):
            if key and any(secret_key in key.lower() for secret_key in SECRET_FIELDS):
                return "***"
            if len(value) > 200:
                return value[:197] + "..."
        return value

    def _supports_form_elicitation(self) -> bool:
        elicitation = self.client_capabilities.get("elicitation")
        if elicitation is None:
            return False
        if elicitation == {}:
            return True
        return isinstance(elicitation, dict) and "form" in elicitation

    def _next_proxy_request_id(self) -> str:
        self.proxy_request_counter += 1
        return f"dualkey-approval-{self.proxy_request_counter}"

    def _open_tty_streams(self) -> tuple[Any, Any] | None:
        try:
            stdin = open("/dev/tty", "r", encoding="utf-8")
            stdout = open("/dev/tty", "w", encoding="utf-8")
        except OSError:
            return None
        return stdin, stdout

    def _is_response(self, message: JsonObject) -> bool:
        return "id" in message and ("result" in message or "error" in message) and "method" not in message

    async def _send_to_server(self, message: JsonObject) -> None:
        assert self.process is not None
        assert self.process.stdin is not None
        payload = self._encode_message(message)
        async with self.server_write_lock:
            self.process.stdin.write(payload)
            await self.process.stdin.drain()

    async def _send_to_client(self, message: JsonObject) -> None:
        payload = self._encode_message(message)
        async with self.client_write_lock:
            sys.stdout.buffer.write(payload)
            sys.stdout.buffer.flush()

    def _encode_message(self, message: JsonObject) -> bytes:
        return json.dumps(message, ensure_ascii=True, separators=(",", ":")).encode("utf-8") + b"\n"

    def _current_session_id(self) -> str:
        client_name = _session_component(self.client_info.get("name"))
        server_name = _session_component(self.server_info.get("name"))
        if client_name and server_name:
            return f"mcp:{client_name}:{server_name}:{self.proxy_run_id}"
        return self.session_id


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DualKey stdio MCP proxy")
    parser.add_argument(
        "--policy",
        required=True,
        help="Path to the DualKey YAML policy",
    )
    parser.add_argument(
        "--receipts",
        default=".dualkey/mcp-proxy-receipts.jsonl",
        help="Path to append receipts (.jsonl, .sqlite, .sqlite3, or .db)",
    )
    parser.add_argument(
        "--approval-mode",
        choices=["auto", "elicitation", "tty", "auto-approve", "auto-deny"],
        default="auto",
        help="How ask decisions should request a second key",
    )
    add_receipt_settings_arguments(parser)
    parser.add_argument(
        "command",
        nargs=argparse.REMAINDER,
        help="Downstream MCP server command after --",
    )
    return parser


async def async_main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("missing downstream MCP server command after --")

    receipt_settings = receipt_settings_from_args(args)
    proxy = MCPProxy(
        policy=load_policy(Path(args.policy)),
        downstream_command=command,
        approval_mode=args.approval_mode,
        receipt_store=ReceiptStore(args.receipts, settings=receipt_settings),
        receipt_settings=receipt_settings,
    )
    return await proxy.run()


def main(argv: list[str] | None = None) -> int:
    return asyncio.run(async_main(argv))


def _session_component(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    normalized = "".join(char if char.isalnum() or char in {"-", "_", "."} else "-" for char in text)
    normalized = normalized.strip("-")
    return normalized or None


if __name__ == "__main__":
    raise SystemExit(main())
