# PRD: Git Push Approval Demo

## Goal

Show, in under 30 seconds, why DualKey exists: a coding agent can edit files and prepare a push, but it cannot push a protected branch without a second key.

## User story

As a developer using an AI coding agent, I want risky git actions to pause with a clear preview so I can approve or reject them before they run.

## Demo scenario

1. A toy coding agent is asked to "fix the bug and open a PR".
2. The agent proposes two actions:
   - write `/repo/.env`
   - run `git push origin main`
3. DualKey evaluates both actions through deterministic policy.
4. The `.env` write is denied because it carries the `secrets` tag.
5. The `git push origin main` action is marked `ask`.
6. DualKey renders a preview containing:
   - actor
   - tool name
   - command
   - target branch
   - matched rule
7. Approval is granted or rejected by a second key.
8. DualKey writes an HMAC-signed receipt.

## Success criteria

- The approval decision is deterministic and tied to a concrete rule.
- The preview shows enough context for a human to make a decision quickly.
- The denial / approval is visible in the console without reading internal logs.
- The receipt contains the action fingerprint, decision path, approver, and timestamp.

## Non-goals for v0.1

- Real git integration.
- Background agent execution.
- Browser UI or inbox.
- Multi-user approval routing.

## Required receipt fields

- `decision`
- `approved_by`
- `approved_at`
- `action_hash`
- `policy_match`
- `trace_id`
- `receipt_hash`

## Why this demo ships first

`git push origin main` is instantly legible to both developers and non-developers. It demonstrates privilege, blast radius, and approval value in one screen without requiring external services.
