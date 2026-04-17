from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policy" / "examples" / "mcp-proxy.yaml"
FIXTURE_SERVER = ROOT / "tests" / "fixtures" / "fake_mcp_server.py"


def _proxy_command() -> list[str]:
    if cli := shutil.which("dualkey-mcp-proxy"):
        return [cli]
    return [sys.executable, "-m", "dualkey.mcp_proxy"]


def _send(process: subprocess.Popen[str], message: dict[str, Any]) -> None:
    assert process.stdin is not None
    process.stdin.write(json.dumps(message, separators=(",", ":")) + "\n")
    process.stdin.flush()


def _recv(process: subprocess.Popen[str]) -> dict[str, Any]:
    assert process.stdout is not None
    line = process.stdout.readline()
    if not line:
        stderr = process.stderr.read() if process.stderr is not None else ""
        raise SystemExit(f"expected MCP proxy output before EOF\nstderr={stderr}")
    return json.loads(line)


def _start_proxy(receipts_path: Path) -> subprocess.Popen[str]:
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    return subprocess.Popen(
        [
            *_proxy_command(),
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


def _initialize_proxy(proxy: subprocess.Popen[str]) -> None:
    _send(
        proxy,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {"elicitation": {"form": {}}},
                "clientInfo": {"name": "smoke-client", "version": "0.0.1"},
            },
        },
    )
    initialize_response = _recv(proxy)
    if initialize_response["result"]["serverInfo"]["name"] != "fake-mcp":
        raise SystemExit(f"unexpected initialize response: {initialize_response}")

    _send(proxy, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    tools_response = _recv(proxy)
    tool_names = {tool["name"] for tool in tools_response["result"]["tools"]}
    expected = {"docs.read", "filesystem.write", "browser.pay"}
    if not expected.issubset(tool_names):
        raise SystemExit(f"unexpected tools/list response: {tools_response}")


def _read_receipts(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> int:
    with TemporaryDirectory(prefix="dualkey-mcp-proxy-smoke-") as tmpdir:
        root = Path(tmpdir)
        receipts_path = root / "mcp-proxy-receipts.jsonl"
        proxy = _start_proxy(receipts_path)
        try:
            _initialize_proxy(proxy)

            _send(
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
            deny_response = _recv(proxy)
            _assert(
                deny_response["result"]["isError"] is True
                and "DualKey blocked" in deny_response["result"]["content"][0]["text"],
                f"unexpected blocked tool response: {deny_response}",
            )

            _send(
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
            elicitation_request = _recv(proxy)
            _assert(
                elicitation_request["method"] == "elicitation/create",
                f"unexpected elicitation request: {elicitation_request}",
            )
            _send(
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
            approve_response = _recv(proxy)
            _assert(
                approve_response["result"]["isError"] is False
                and "downstream executed browser.pay" in approve_response["result"]["content"][0]["text"],
                f"unexpected approved tool response: {approve_response}",
            )

            receipts = _read_receipts(receipts_path)
            _assert(receipts[0]["decision"] == "deny", f"missing deny receipt: {receipts!r}")
            _assert(receipts[1]["decision"] == "ask->approved", f"missing approval receipt: {receipts!r}")
            _assert(receipts[1]["approved_by"] == "human:elicitation", f"missing approver: {receipts!r}")
        finally:
            proxy.kill()
            proxy.wait()

    print("dualkey-mcp-proxy smoke checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
