# Security Policy

## Reporting vulnerabilities

Do not open public issues for vulnerabilities that could expose:

- live credentials or secrets
- unsafe agent execution paths
- sandbox escape or remote code execution paths
- receipt forgery or verification bypasses
- approval bypasses or policy-evaluation inconsistencies that materially weaken guarantees

Instead, report them privately to the maintainers through the repository's private security reporting channel once the repository is published.

## What to include

Please include:

- affected version or commit
- clear reproduction steps
- impact assessment
- whether the issue requires real credentials, a real MCP server, or a specific adapter runtime
- any logs or receipts with secrets removed

## Disclosure expectations

- We prefer coordinated disclosure.
- Do not publish exploit details until a fix or mitigation is available.
- If a report includes unsafe payloads or secrets, sanitize them before sharing.

## Scope

The following areas are security-sensitive by default:

- policy allow / ask / deny behavior
- adapter execution boundaries
- receipt signing and verification
- replay and bundle export integrity
- CLI flows that approve or forward actions
