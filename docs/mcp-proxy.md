# DualKey MCP Proxy

## What it is

`dualkey-mcp-proxy` is a stdio MCP proxy that sits in front of a real MCP server. It intercepts `tools/call`, converts the request into a DualKey `ActionEnvelope`, evaluates deterministic policy, optionally asks for a second key via MCP `elicitation/create`, then either forwards the tool call or blocks it with a tool error result.

## Why start here

This is the cleanest first real integration point:

- it works with any MCP-capable host, not just one coding product
- it intercepts the exact execution boundary that matters: `tools/call`
- MCP clients can already provide user-facing approval UI via elicitation

The latest MCP spec keeps stdio newline-delimited JSON-RPC for local servers, defines `tools/call` with `{name, arguments}`, and lets servers request user input through `elicitation/create` during a request flow. DualKey uses that surface directly.

## Current behavior

1. Proxy forwards `initialize`, `tools/list`, and all non-tool traffic.
2. Proxy caches tool definitions returned by `tools/list`.
3. On `tools/call`, the proxy:
   - derives `intent`, `target`, and `risk` tags from tool metadata and arguments
   - builds an `ActionEnvelope`
   - evaluates the configured policy
   - if decision is `ask`, requests approval from the client via form-mode elicitation when supported
   - forwards allowed calls to the downstream MCP server
   - writes receipts for blocked, executed, tool-error, and protocol-error outcomes

## Session metadata

After the `initialize` handshake completes, DualKey stops using a generic proxy session placeholder and derives MCP session context from the real connection:

- `session_id=mcp:<client-name>:<server-name>:<proxy-run-id>`
- `metadata.mcp_client_info`
- `metadata.mcp_client_protocol_version`
- `metadata.mcp_server_info`
- `metadata.mcp_server_protocol_version`
- `metadata.mcp_request_id`
- `metadata.mcp_downstream_command`
- `metadata.mcp_tool_annotations`
- `metadata.mcp_tool_input_schema`

This makes receipts and trace ids much easier to filter when one proxy instance is protecting multiple MCP surfaces over time.

## Example

Run a downstream stdio MCP server through DualKey:

```bash
dualkey-mcp-proxy \
  --policy /absolute/path/policy/examples/mcp-proxy.yaml \
  --receipts /absolute/path/.dualkey/mcp-receipts.sqlite \
  -- \
  python3 /absolute/path/to/server.py
```

Any receipt path ending in `.sqlite`, `.sqlite3`, or `.db` uses the SQLite backend automatically. Keep `.jsonl` when you want line-oriented demo artifacts instead.

## Claude Code example

Point Claude Code at the proxy instead of the raw server:

```json
{
  "mcpServers": {
    "github-guarded": {
      "command": "dualkey-mcp-proxy",
      "args": [
        "--policy",
        "/absolute/path/to/policy/examples/mcp-proxy.yaml",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-github"
      ]
    }
  }
}
```

## Approval modes

- `auto`: use MCP form elicitation if the client declares it, otherwise fall back to `/dev/tty`, otherwise reject
- `elicitation`: require MCP elicitation support
- `tty`: require a local terminal second key
- `auto-approve`: approve all `ask` decisions
- `auto-deny`: reject all `ask` decisions

## Important caveat

MCP tool annotations are hints, not trust anchors. DualKey uses them to derive ergonomic defaults for `intent` and `risk`, but hard guarantees should come from explicit policy rules on tool names, targets, and argument patterns.

## Tests

The repo already includes real subprocess integration tests for the proxy path. They launch:

- the actual `dualkey.mcp_proxy` module
- a downstream stdio fixture server
- real JSON-RPC `initialize`, `tools/list`, and `tools/call` flows

Run them with:

```bash
python3 -m pytest -q tests/test_mcp_proxy.py
```

CI also runs `python3 scripts/mcp_proxy_smoke.py`, which drives the installed `dualkey-mcp-proxy` entrypoint through a real `initialize -> tools/list -> tools/call` flow against the bundled fake MCP server.
