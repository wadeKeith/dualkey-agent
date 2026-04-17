from __future__ import annotations

import json
import sys


TOOLS = [
    {
        "name": "docs.read",
        "description": "Read a document from the workspace",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
            },
            "required": ["path"],
        },
        "annotations": {
            "readOnlyHint": True,
            "destructiveHint": False,
            "openWorldHint": False,
        },
    },
    {
        "name": "filesystem.write",
        "description": "Write content to a file",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["path", "content"],
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": False,
            "openWorldHint": False,
        },
    },
    {
        "name": "browser.pay",
        "description": "Click the pay now button in checkout",
        "inputSchema": {
            "type": "object",
            "properties": {
                "selector": {"type": "string"},
                "amount": {"type": "string"},
            },
            "required": ["selector"],
        },
        "annotations": {
            "readOnlyHint": False,
            "destructiveHint": True,
            "openWorldHint": True,
        },
    },
]


def send(message: dict) -> None:
    sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
    sys.stdout.flush()


for raw in sys.stdin:
    if not raw.strip():
        continue
    message = json.loads(raw)
    if message["method"] == "initialize":
        send(
            {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "protocolVersion": message["params"].get("protocolVersion", "2025-06-18"),
                    "capabilities": {"tools": {"listChanged": True}},
                    "serverInfo": {"name": "fake-mcp", "version": "0.1.0"},
                },
            }
        )
    elif message["method"] == "tools/list":
        send({"jsonrpc": "2.0", "id": message["id"], "result": {"tools": TOOLS}})
    elif message["method"] == "tools/call":
        tool_name = message["params"]["name"]
        arguments = message["params"].get("arguments", {})
        send(
            {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": f"downstream executed {tool_name} with {json.dumps(arguments, sort_keys=True)}",
                        }
                    ],
                    "isError": False,
                },
            }
        )
