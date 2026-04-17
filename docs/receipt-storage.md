# DualKey Receipt Storage

## Formats

DualKey now supports two receipt backends behind the same `ReceiptStore(path)` API:

- `.jsonl` for simple local inspection and demos
- `.sqlite`, `.sqlite3`, or `.db` for append-safe storage with indexed query fields

Path suffix decides the backend. No extra flag is required.

## JSONL

JSONL remains the default because it is easy to inspect, diff, and attach to demos:

```bash
dualkey-demo git-push --receipts .dualkey/demo-receipts.jsonl
```

## SQLite

SQLite is better once receipts become an audit surface instead of a demo artifact:

```bash
dualkey-mcp-proxy \
  --policy /absolute/path/policy/examples/mcp-proxy.yaml \
  --receipts /absolute/path/.dualkey/mcp-proxy-receipts.sqlite \
  -- \
  python3 /absolute/path/to/server.py
```

DualKey stores the full signed payload as JSON and also writes queryable columns:

- `created_at`
- `trace_id`
- `action_hash`
- `decision`
- `policy_match`
- `status`
- `approved_by`
- `approved_at`
- `result_preview`
- `error`
- `receipt_hash`

It also creates indexes on:

- `created_at`
- `trace_id`
- `action_hash`
- `status`
- `decision`
- `policy_match`

## Hygiene controls

Redaction and retention are configured through environment variables so existing adapters and CLIs do not need extra wiring:

- `DUALKEY_RECEIPT_REDACTION=off` disables built-in secret redaction for `result_preview` and `error`
- `DUALKEY_RECEIPT_RETENTION_DAYS=30` keeps only the last N days
- `DUALKEY_RECEIPT_MAX_RECEIPTS=10000` keeps only the newest N receipts

These rules apply to both JSONL and SQLite backends. Redaction happens before signing, so stored payloads and receipt hashes stay aligned.

The built-in CLIs also expose explicit flags:

- `--receipt-redaction on|off`
- `--receipt-retention-days N`
- `--receipt-max-receipts N`

If you are calling DualKey from Python instead of a CLI, pass the same controls explicitly:

```python
from dualkey import ReceiptSettings, ReceiptStore

store = ReceiptStore(
    ".dualkey/receipts.sqlite",
    settings=ReceiptSettings(
        retention_days=30,
        max_receipts=10000,
        redact_sensitive_values=True,
    ),
)
```

## Querying receipts

The repo now includes a small query CLI:

```bash
dualkey-receipts .dualkey/receipts.sqlite --trace-id openhands:call_pending_1
dualkey-receipts .dualkey/receipts.jsonl --status blocked --decision deny --format json
dualkey-receipts .dualkey/receipts.sqlite --trace-id openhands:call_pending_1 --format timeline
dualkey-receipts .dualkey/receipts.sqlite --trace-id openhands:call_pending_1 --format markdown --output ./audit-report.md
dualkey-receipts .dualkey/receipts.sqlite --trace-id openhands:call_pending_1 --format bundle --output ./audit-bundle
dualkey-replay ./audit-bundle --trace-id openhands:call_pending_1
dualkey-replay ./audit-bundle --trace-id openhands:call_pending_1 --tool bash --target-contains .env
dualkey-replay ./audit-bundle --trace-id openhands:call_pending_1 --metadata-path workspace.root --metadata-contains /repo --show-metadata
dualkey-replay ./audit-bundle --trace-id openhands:call_pending_1 --format html --output ./audit-view.html --show-metadata
dualkey-verify ./audit-bundle
dualkey-verify .dualkey/receipts.sqlite --format json
```

Supported filters:

- `--trace-id`
- `--action-hash`
- `--status`
- `--decision`
- `--policy-match`
- `--limit`
- `--order asc|desc`
- `--format table|json|jsonl|timeline|markdown|bundle`
- `--output /path/to/report.md`

The same filtering surface is also available from Python through `ReceiptStore.query_payloads(ReceiptQuery(...))`. If you want grouped execution chains instead of flat rows, use `ReceiptStore.build_traces(ReceiptQuery(...))` and inspect the returned `ReceiptTrace` objects. If you want a shareable audit artifact, call `ReceiptStore.render_report(ReceiptQuery(...))`. If you want a complete bundle with report, timeline, raw receipts, and a manifest, use `ReceiptStore.export_bundle(...)` or export the CLI output with `--format bundle --output ...`.

Replay is read-only. `dualkey-replay` can read either a live receipt store or a previously exported bundle directory / `manifest.json`, then render the trace with step deltas so you can inspect how a decision chain unfolded without re-executing any action. New receipts now carry an `action_summary` overlay, so replay can also filter at the event level with flags like `--actor`, `--surface`, `--tool`, `--intent`, `--risk`, `--target-contains`, `--metadata-path`, and `--metadata-contains`. Use `--show-metadata` when you want the summarized adapter metadata rendered inline in the replay output, or `--format html --output ...` when you want a static single-file viewer you can open in a browser. The exported viewer now includes client-side search, exact filters, metadata toggles, and trace expand/collapse controls without needing any extra assets. When you need to validate integrity rather than inspect behavior, `dualkey-verify` will re-check receipt HMACs, bundle manifest signatures, and exported file hashes.

The repo also includes `scripts/verify_smoke.py`. CI runs it after `pytest` so the packaged `dualkey-verify` CLI has to keep detecting both valid and tampered stores / bundles, not just pass unit tests through internal helper calls.

## Current scope

This storage upgrade is still intentionally narrow:

- it preserves the existing append-only receipt model
- it applies retention only by age or count
- it redacts `result_preview` and `error`, not arbitrary custom payload fields

Those are the next steps once the repo needs stronger production hygiene.
