# DualKey Policy Language

DualKey rules are intentionally small and deterministic. Each rule has a `when` object and one `decision`: `allow`, `ask`, or `deny`.

## Core fields

- exact fields: `actor`, `surface`, `tool`, `intent`
- glob fields: `actor_glob`, `surface_glob`, `tool_glob`, `intent_glob`
- target fields: `target_prefix`, `target_glob`, `target_regex`
- risk fields: `tags_any`, `tags_all`, `tags_none`

## Nested path matching

`arg_*` and `metadata_*` rules use dotted paths into nested objects:

- `command`
- `file_path`
- `questions.0.question`
- `annotations.readOnlyHint`

Supported matchers:

- `arg_equals`
- `arg_prefix`
- `arg_contains`
- `arg_glob`
- `arg_regex`
- `arg_exists`
- `metadata_equals`
- `metadata_contains`
- `metadata_glob`
- `metadata_regex`
- `metadata_exists`

## Examples

Allow all read tools from Claude Code:

```yaml
- id: claude_reads
  when:
    actor: claude-code
    tool_glob:
      - Read
      - Grep
      - Glob
      - LS
  decision: allow
```

Ask before a Bash push to `main`:

```yaml
- id: push_main_requires_approval
  when:
    tool: Bash
    arg_regex:
      command: "(^|\\s)git\\s+push\\s+\\S+\\s+main(\\s|$)"
  decision: ask
```

Deny writes to secret-like files:

```yaml
- id: no_secret_writes
  when:
    tool_glob:
      - Write
      - Edit
      - MultiEdit
    target_glob:
      - "*/.env"
      - "*/.env.*"
      - "*/.ssh/*"
  decision: deny
```

Match on hook metadata:

```yaml
- id: only_affect_permission_requests
  when:
    metadata_equals:
      hook_event_name: PermissionRequest
    tool_glob: "Web*"
  decision: ask
```

## Debugging a rule hit

Use `dualkey-policy eval` when you want to see not just the final decision, but also which earlier rules failed and why:

```bash
printf '%s\n' '{"actor":"claude-code","surface":"claude-code","tool":"Bash","intent":"execute","args":{"command":"git push origin main"}}' \
  | dualkey-policy eval --policy policy/examples/claude-code.yaml
```

Add `--format json` if you want machine-readable output for tests or CI.

## Regressing a full policy

For repeatable checks, put a suite of fixtures in a file:

```yaml
cases:
  - id: push_main
    action:
      actor: claude-code
      surface: claude-code
      tool: Bash
      intent: execute
      args:
        command: git push origin main
    expect:
      decision: ask
      rule_id: push_main_requires_approval
```

Then run:

```bash
dualkey-policy test --policy policy/examples/claude-code.yaml --cases ./policy-cases.yaml
```

Use `--fail-fast` if you want the run to stop on the first mismatch.
The repo also includes ready-made fixture suites under `policy/examples/*-tests.yaml`, and CI runs them against the matching example policies.
