# DualKey Claude Code Hook Adapter

## What it is

`dualkey-claude-hook` is a single hook command that maps Claude Code hook payloads into DualKey `ActionEnvelope`s, evaluates the same deterministic policy used elsewhere in the repo, and appends signed receipts for permission and execution events.

It currently handles:

- `PreToolUse`
- `PermissionRequest`
- `PostToolUse`
- `PostToolUseFailure`
- `PermissionDenied`

## Why this shape

Claude Code splits tool governance across multiple hook events:

- `PreToolUse` is the earliest preflight point.
- `PermissionRequest` is the actual permission surface shown to the user.
- `PostToolUse` and `PostToolUseFailure` let DualKey record what actually happened.
- `PermissionDenied` captures auto-mode classifier denials.

Using one hook command for all of them keeps policy and receipt semantics consistent across the full lifecycle.

## Example config

Add this command hook to Claude Code:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "dualkey-claude-hook --policy /absolute/path/to/policy/examples/claude-code.yaml"
          }
        ]
      }
    ],
    "PermissionRequest": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "dualkey-claude-hook --policy /absolute/path/to/policy/examples/claude-code.yaml --echo-first-suggestion"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "dualkey-claude-hook --policy /absolute/path/to/policy/examples/claude-code.yaml"
          }
        ]
      }
    ],
    "PostToolUseFailure": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "dualkey-claude-hook --policy /absolute/path/to/policy/examples/claude-code.yaml"
          }
        ]
      }
    ],
    "PermissionDenied": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "dualkey-claude-hook --policy /absolute/path/to/policy/examples/claude-code.yaml"
          }
        ]
      }
    ]
  }
}
```

If you want a queryable audit store instead of line-oriented logs, add `--receipts /absolute/path/.dualkey/claude-code-receipts.sqlite`. Receipt backend selection is suffix-based, so `.jsonl` stays JSONL and `.sqlite` or `.db` switches to SQLite automatically.

## Current behavior

### `PreToolUse`

- builds an `ActionEnvelope` from `tool_name`, `tool_input`, and common hook metadata
- evaluates policy
- returns `permissionDecision: allow | deny | ask`
- writes a `claude_pre_tool_use` receipt

### `PermissionRequest`

- evaluates the same policy against the permission-surface payload
- returns an allow/deny decision only when the policy is deterministic
- leaves `ask` requests untouched so Claude can show the normal prompt
- optionally echoes the first `permission_suggestions` entry back as `updatedPermissions`
- writes a `claude_permission_request` receipt

### `PostToolUse` / `PostToolUseFailure`

- records executed and failed tool outcomes into signed receipts
- keeps `tool_response` or failure text attached to the receipt

## Example policy ideas

- allow `Read`, `Grep`, `Glob`, and `LS`
- deny writes to `.env`, `.ssh`, or key material
- deny `Bash` commands that match `rm -rf`
- ask before `git push origin main`
- ask before `WebFetch` and `WebSearch`

## Caveat

`PermissionRequest` hooks can only return allow or deny. If DualKey policy resolves to `ask`, the adapter intentionally returns no decision so Claude shows the built-in permission dialog.

## Tests

The repo already includes subprocess tests for the hook module, and CI now also runs `python3 scripts/claude_hook_smoke.py` so the installed `dualkey-claude-hook` entrypoint has to keep handling both deny and allow payloads correctly.
