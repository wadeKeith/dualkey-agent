---
name: Release Checklist
about: Track the required checks before cutting a DualKey release.
title: "release: <version>"
labels: release
assignees: ''
---

# DualKey Release Checklist

Release target: `<version>`

## Release metadata

- [ ] Version number is final.
- [ ] Release notes / changelog entry are drafted.
- [ ] Any migration or rollout notes are linked in this issue.

## Automated Gate (`pending`)

Copy the latest CI artifact or re-run `python3 scripts/release_gate.py --status passed` before checking boxes below.

### Core

- [ ] Unit tests
  Command: `python -m pytest -q`
  Scope: Run the core DualKey test suite on Python 3.11 and 3.12.
  Source: `ci:test`
- [ ] Policy fixture regressions
  Command: `dualkey-policy test --policy policy/examples/<name>.yaml --cases policy/examples/<name>-tests.yaml --fail-fast`
  Scope: Verify every shipped example policy still matches its expected decisions.
  Source: `ci:test`
- [ ] Receipt integrity smoke
  Command: `python scripts/verify_smoke.py`
  Scope: Confirm dualkey-verify still accepts valid stores and rejects tampered stores and bundles.
  Source: `ci:test`
- [ ] Packaging smoke
  Command: `python scripts/package_smoke.py`
  Scope: Build the sdist and wheel, then run twine check against the generated artifacts.
  Source: `ci:test`
### Adapters

- [ ] Claude Code hook CLI smoke
  Command: `python scripts/claude_hook_smoke.py`
  Scope: Exercise the installed dualkey-claude-hook entrypoint with deny and allow payloads.
  Source: `ci:adapter-compat`
- [ ] MCP proxy CLI smoke
  Command: `python scripts/mcp_proxy_smoke.py`
  Scope: Drive the installed dualkey-mcp-proxy through initialize, tools/list, blocked tool calls, and elicitation approval.
  Source: `ci:adapter-compat`
- [ ] browser-use runtime compatibility
  Command: `python -m pytest -q tests/test_browser_use_runtime_compat.py`
  Scope: Check the public browser-use Tools registry and ActionResult import path against the real package.
  Source: `ci:adapter-compat`
- [ ] OpenHands real SDK compatibility
  Command: `python -m pytest -q tests/test_openhands_sdk_integration.py`
  Scope: Verify the real OpenHands LocalConversation boundary and confirmation receipts on Python 3.12.
  Source: `ci:adapter-compat`

## Approval

- [ ] A maintainer confirmed the gate is green and the release can be cut.
