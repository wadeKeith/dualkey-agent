# browser-use Adapter

`guard_browser_use_tools()` connects DualKey to `browser-use` without forking the runtime. It wraps `tools.registry.execute_action`, which is the common execution surface for built-in and custom actions, and routes each action through the same `ActionEnvelope -> policy -> approval -> receipt` pipeline already used by the MCP proxy and Claude Code hook.

## Why this integration point

`browser-use` exposes actions through `Tools().registry.action(...)`, and the registry service executes them through `execute_action(...)`. That makes the registry boundary the narrowest place to add:

- deterministic allow / ask / deny policy
- action previews before risky clicks or uploads
- signed receipts for blocked and executed browser steps

## Minimal setup

```python
from browser_use import Agent, ChatBrowserUse, Tools
from dualkey import guard_browser_use_tools

tools = Tools()
guard_browser_use_tools(
    tools,
    policy="policy/examples/browser-use.yaml",
    approval_mode="tty",
)

agent = Agent(
    task="buy the cheapest red mug, but stop before payment",
    llm=ChatBrowserUse(),
    tools=tools,
)
```

If you want to validate the adapter against the real `browser-use` package instead of the fake registry used by the unit tests, install the optional dependency set and run the compatibility smoke:

```bash
python3 -m pip install -e '.[browser-use]'
python3 -m pytest -q tests/test_browser_use_runtime_compat.py
```

## What DualKey extracts

For each `browser-use` action, the adapter builds an `ActionEnvelope` with:

- `actor=browser-use`
- `surface=browser-use`
- `tool=<action name>`
- `intent` derived from the action class, such as `navigate`, `read`, `write`, or `execute`
- `target` from high-signal params like `url`, `path`, `selector`, or `text`
- `metadata.page_url` from `browser_session.get_current_page_url()`
- risk tags such as `payment`, `network`, `filesystem`, `secrets`, and `script`

That means the same matcher language works across browser-use, MCP, and Claude Code:

```yaml
default_decision: ask
rules:
  - id: checkout_requires_second_key
    when:
      actor: browser-use
      tool: click
      metadata_glob:
        page_url: "https://shop.example.com/checkout*"
      arg_glob:
        selector: "*pay*"
    decision: ask

  - id: block_secret_uploads
    when:
      actor: browser-use
      tool_in: ["upload_file", "write_file"]
      target_glob: ["*.env", "*/.ssh/*"]
    decision: deny
```

## Approval modes

- `tty`: show a console prompt on `/dev/tty` when policy returns `ask`
- `auto`: use `/dev/tty` when available, otherwise reject
- `auto-approve`: approve every `ask`
- `auto-deny`: reject every `ask`

## Receipts

By default, receipts go to `.dualkey/browser-use-receipts.jsonl`. If you pass a path ending in `.sqlite`, `.sqlite3`, or `.db`, DualKey will store the same signed receipts in SQLite instead. Each entry records:

- policy match
- final decision
- approver identity when a second key was used
- result preview or tool error
- HMAC receipt hash

## Notes

- The adapter does not replace `browser-use` domain scoping. Keep using the native `domains` / `allowed_domains` controls and treat DualKey as the approval and evidence layer on top.
- If `browser-use` is not installed, you can still test the adapter by providing a custom `blocked_result_factory`, which is how the repository tests isolate the integration.
- CI now runs a real `browser-use` compatibility job on Python 3.11 so the public `Tools()` registry shape and `ActionResult` import path stay pinned to a known-good series.
