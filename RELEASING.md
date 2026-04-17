# Releasing DualKey

## 1. Prepare the version

- Update `version` in [pyproject.toml](./pyproject.toml).
- Move release notes from `Unreleased` into a dated version section in [CHANGELOG.md](./CHANGELOG.md).
- Open the release checklist issue from [`.github/ISSUE_TEMPLATE/release-checklist.md`](./.github/ISSUE_TEMPLATE/release-checklist.md).

## 2. Run local release checks

```bash
python3 -m pip install -e '.[dev]'
python3 -m pytest -q
python3 scripts/verify_smoke.py
python3 scripts/package_smoke.py
python3 scripts/release_gate.py --status passed --output ./release-gate.md
```

If the change touches adapter entrypoints or compatibility-sensitive surfaces, also run:

```bash
python3 scripts/claude_hook_smoke.py
python3 scripts/mcp_proxy_smoke.py
python3 -m pytest -q tests/test_browser_use_runtime_compat.py
python3 -m pytest -q tests/test_openhands_sdk_integration.py
```

## 3. Confirm CI

- Wait for `test`, `adapter-compat`, and `release-gate` to pass.
- Download the `release-gate` artifact if you want the exact gate snapshot used by CI.

## 4. Build the artifacts

`python3 scripts/package_smoke.py` already does:

- `python -m build --sdist --wheel`
- `python -m twine check dist/*`

If you want to inspect the artifacts manually, they will be under `dist/`.

## 5. Publish

Once the repository and package destinations are configured:

- create the git tag for the release
- publish the source distribution and wheel to your package index
- create the GitHub release using the matching changelog entry

## 6. After publishing

- reset `CHANGELOG.md` with a fresh `Unreleased` section
- update any version-specific examples if needed
- close the release checklist issue
