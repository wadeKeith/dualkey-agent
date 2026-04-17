# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project follows Semantic Versioning.

## [Unreleased]

## [0.1.1] - 2026-04-17

### Added

- README badges and first-screen demo placeholders for the public repository.

### Changed

- Replaced local absolute documentation links with GitHub-safe relative links.

## [0.1.0] - 2026-04-17

### Added

- Deterministic `ActionEnvelope -> policy -> approval -> receipt` core.
- CLI adapters for MCP proxy and Claude Code hook.
- Runtime adapters for `browser-use` and `OpenHands`.
- Signed receipt storage with JSONL / SQLite backends, query CLI, replay CLI, HTML audit viewer, bundle export, and verification.
- Policy explanation, fixture testing, and CI regression coverage for shipped example policies.
- Compatibility smoke coverage for Claude Code hook, MCP proxy, `browser-use`, and `OpenHands`.
- Release gate rendering, release checklist issue template, and integrity/package smoke coverage in CI.
