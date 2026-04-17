from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

from dualkey.mcp_proxy import MCPProxy
from dualkey.policy import Policy


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "sdk" / "python" / "src"
FIXTURE_SERVER = ROOT / "tests" / "fixtures" / "fake_mcp_server.py"
POLICY_PATH = ROOT / "policy" / "examples" / "mcp-proxy.yaml"


def send(process: subprocess.Popen[str], message: dict[str, Any]) -> None:
    assert process.stdin is not None
    process.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
    process.stdin.flush()


def recv(process: subprocess.Popen[str]) -> dict[str, Any]:
    assert process.stdout is not None
    line = process.stdout.readline()
    assert line, "expected proxy output before EOF"
    return json.loads(line)


def start_proxy(tmp_path: Path) -> tuple[subprocess.Popen[str], Path]:
    receipts_path = tmp_path / "mcp-proxy-receipts.jsonl"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC)
    env["PYTHONUNBUFFERED"] = "1"
    proxy = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "dualkey.mcp_proxy",
            "--policy",
            str(POLICY_PATH),
            "--receipts",
            str(receipts_path),
            "--approval-mode",
            "elicitation",
            "--",
            sys.executable,
            str(FIXTURE_SERVER),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    return proxy, receipts_path


def initialize_proxy(proxy: subprocess.Popen[str]) -> None:
    send(
        proxy,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"elicitation": {"form": {}}},
                "clientInfo": {"name": "test-client", "version": "0.0.1"},
            },
        },
    )
    response = recv(proxy)
    assert response["id"] == 1
    assert response["result"]["serverInfo"]["name"] == "fake-mcp"

    send(proxy, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    tools_response = recv(proxy)
    assert tools_response["id"] == 2
    assert len(tools_response["result"]["tools"]) == 3


def test_mcp_proxy_builds_real_session_metadata_after_initialize() -> None:
    proxy = MCPProxy(
        policy=Policy.from_mapping({"default_decision": "allow", "rules": []}),
        downstream_command=["python3", "/tmp/fake-mcp.py"],
        approval_mode="auto-approve",
    )
    proxy.client_info = {"name": "test-client", "version": "0.0.1"}
    proxy.client_protocol_version = "2025-11-25"
    proxy.server_info = {"name": "fake-mcp", "version": "0.1.0"}
    proxy.server_protocol_version = "2025-11-25"

    envelope = proxy._build_action_envelope(
        tool_name="browser.pay",
        arguments={"selector": "button#pay-now", "amount": "149.00"},
        tool_def={
            "description": "Click the pay now button in checkout",
            "inputSchema": {
                "type": "object",
                "properties": {"selector": {"type": "string"}},
            },
            "annotations": {"destructiveHint": True, "openWorldHint": True},
        },
        request_id=7,
    )

    assert envelope.session_id.startswith("mcp:test-client:fake-mcp:")
    assert envelope.trace_id == f"{envelope.session_id}:7"
    assert envelope.metadata["mcp_client_info"] == {"name": "test-client", "version": "0.0.1"}
    assert envelope.metadata["mcp_server_info"] == {"name": "fake-mcp", "version": "0.1.0"}
    assert envelope.metadata["mcp_client_protocol_version"] == "2025-11-25"
    assert envelope.metadata["mcp_server_protocol_version"] == "2025-11-25"
    assert envelope.metadata["mcp_request_id"] == "7"
    assert envelope.metadata["mcp_downstream_command"] == ["python3", "/tmp/fake-mcp.py"]


def test_mcp_proxy_denies_secret_file_write(tmp_path: Path) -> None:
    proxy, receipts_path = start_proxy(tmp_path)
    try:
        initialize_proxy(proxy)
        send(
            proxy,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "filesystem.write",
                    "arguments": {"path": "/repo/.env", "content": "TOKEN=supersecret"},
                },
            },
        )
        response = recv(proxy)
        assert response["id"] == 3
        assert response["result"]["isError"] is True
        assert "DualKey blocked" in response["result"]["content"][0]["text"]

        receipts = [json.loads(line) for line in receipts_path.read_text(encoding="utf-8").splitlines()]
        assert receipts[0]["decision"] == "deny"
        assert receipts[0]["status"] == "blocked"
        assert receipts[0]["trace_id"].startswith("mcp:test-client:fake-mcp:")
    finally:
        proxy.kill()
        proxy.wait()


def test_mcp_proxy_approves_via_elicitation_and_forwards_tool(tmp_path: Path) -> None:
    proxy, receipts_path = start_proxy(tmp_path)
    try:
        initialize_proxy(proxy)
        send(
            proxy,
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "browser.pay",
                    "arguments": {"selector": "button#pay-now", "amount": "149.00"},
                },
            },
        )

        elicitation_request = recv(proxy)
        assert elicitation_request["method"] == "elicitation/create"
        assert "DualKey approval required" in elicitation_request["params"]["message"]

        send(
            proxy,
            {
                "jsonrpc": "2.0",
                "id": elicitation_request["id"],
                "result": {
                    "action": "accept",
                    "content": {"decision": "approve", "note": "looks fine"},
                },
            },
        )

        tool_response = recv(proxy)
        assert tool_response["id"] == 4
        assert tool_response["result"]["isError"] is False
        assert "downstream executed browser.pay" in tool_response["result"]["content"][0]["text"]

        receipts = [json.loads(line) for line in receipts_path.read_text(encoding="utf-8").splitlines()]
        assert receipts[0]["decision"] == "ask->approved"
        assert receipts[0]["status"] == "executed"
        assert receipts[0]["approved_by"] == "human:elicitation"
        assert receipts[0]["trace_id"].startswith("mcp:test-client:fake-mcp:")
    finally:
        proxy.kill()
        proxy.wait()
