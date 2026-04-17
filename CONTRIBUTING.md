# Contributing

## Before you start

- Read [README.md](/Users/yin/Documents_local/Github/DualKey/README.md) for the project shape and supported adapters.
- Read [SECURITY.md](/Users/yin/Documents_local/Github/DualKey/SECURITY.md) before opening issues about vulnerabilities or unsafe agent behavior.
- If your change affects release criteria, check [scripts/release_gate.py](/Users/yin/Documents_local/Github/DualKey/scripts/release_gate.py).

## Development setup

Install the base dev environment:

```bash
python3 -m pip install -e '.[dev]'
```

Optional compatibility environments:

```bash
python3 -m pip install -e '.[browser-use]'
python3 -m pip install -e '.[openhands]'
```

`openhands-sdk` currently requires Python 3.12+, so use a 3.12 environment for that extra.

## What to run before opening a PR

Minimum:

```bash
python3 -m pytest -q
python3 scripts/verify_smoke.py
python3 scripts/package_smoke.py
```

If you changed policies or matchers:

```bash
for base in dualkey claude-code browser-use mcp-proxy openhands; do
  dualkey-policy test \
    --policy "policy/examples/${base}.yaml" \
    --cases "policy/examples/${base}-tests.yaml" \
    --fail-fast
done
```

If you changed adapter entrypoints:

```bash
python3 scripts/claude_hook_smoke.py
python3 scripts/mcp_proxy_smoke.py
python3 -m pytest -q tests/test_browser_use_runtime_compat.py
python3 -m pytest -q tests/test_openhands_sdk_integration.py
```

## Pull requests

- Keep PRs scoped. One adapter, one receipt feature, or one policy-language change per PR is usually right.
- Include the behavior change, risks, and verification commands in the PR body.
- Update docs when changing CLI flags, policy semantics, receipts, or release criteria.
- Add or update tests with every behavior change.

## Policy changes

DualKey's policy surface is part of the product, not just an implementation detail. If you change matcher semantics or example policies:

- explain the change in the PR
- update fixture files under `policy/examples/*-tests.yaml`
- make sure `dualkey-policy eval` and `dualkey-policy test` still tell a coherent story

## Receipts and security-sensitive changes

Changes to redaction, verification, replay, approval behavior, or adapter execution boundaries need extra care:

- prefer deterministic tests over screenshots
- include at least one tamper or denial case when relevant
- verify that signed receipts still round-trip through query / replay / verify flows

## Release-facing changes

If your change affects release readiness, update:

- [CHANGELOG.md](/Users/yin/Documents_local/Github/DualKey/CHANGELOG.md)
- [scripts/release_gate.py](/Users/yin/Documents_local/Github/DualKey/scripts/release_gate.py)
- [`.github/ISSUE_TEMPLATE/release-checklist.md`](/Users/yin/Documents_local/Github/DualKey/.github/ISSUE_TEMPLATE/release-checklist.md)
