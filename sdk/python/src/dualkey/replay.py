from __future__ import annotations

import argparse
from datetime import datetime, timezone
from html import escape
import json
from pathlib import Path
from typing import Any

from dualkey.receipts import ReceiptQuery, ReceiptStore, ReceiptTrace


def build_replay_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Replay DualKey receipt traces from a store or audit bundle")
    parser.add_argument("source", help="Path to a receipt store, bundle directory, or bundle manifest.json")
    parser.add_argument("--trace-id", default=None, help="Filter by trace_id")
    parser.add_argument("--action-hash", default=None, help="Filter by action_hash")
    parser.add_argument("--status", default=None, help="Filter by receipt status")
    parser.add_argument("--decision", default=None, help="Filter by decision")
    parser.add_argument("--policy-match", default=None, help="Filter by policy rule id")
    parser.add_argument("--actor", default=None, help="Event-level filter on action_summary.actor")
    parser.add_argument("--surface", default=None, help="Event-level filter on action_summary.surface")
    parser.add_argument("--tool", default=None, help="Event-level filter on action_summary.tool")
    parser.add_argument("--intent", default=None, help="Event-level filter on action_summary.intent")
    parser.add_argument("--risk", default=None, help="Event-level filter requiring a risk tag")
    parser.add_argument("--target-contains", default=None, help="Event-level substring filter on action_summary.target")
    parser.add_argument("--metadata-path", default=None, help="Event-level dotted path inside action_summary.metadata")
    parser.add_argument("--metadata-contains", default=None, help="Event-level substring filter on action_summary.metadata")
    parser.add_argument("--show-metadata", action="store_true", help="Render summarized action metadata in text replay output")
    parser.add_argument("--limit", type=_nonnegative_int, default=None, help="Return at most N receipts")
    parser.add_argument(
        "--order",
        choices=["asc", "desc"],
        default="asc",
        help="Sort by created_at",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json", "html"],
        default="text",
        help="How to render the replay output",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Write the rendered replay to a file instead of stdout",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_replay_parser()
    args = parser.parse_args(argv)

    source_path = Path(args.source)
    query = ReceiptQuery(
        trace_id=args.trace_id,
        action_hash=args.action_hash,
        status=args.status,
        decision=args.decision,
        policy_match=args.policy_match,
        limit=args.limit,
        descending=args.order == "desc",
    )
    source_info, traces = _load_replay_source(source_path, query)
    traces = _filter_traces(
        traces,
        actor=args.actor,
        surface=args.surface,
        tool=args.tool,
        intent=args.intent,
        risk=args.risk,
        target_contains=args.target_contains,
        metadata_path=args.metadata_path,
        metadata_contains=args.metadata_contains,
    )
    output = _render_replay(
        traces,
        source_info=source_info,
        output_format=args.format,
        show_metadata=args.show_metadata or args.metadata_path is not None or args.metadata_contains is not None,
    )
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output, encoding="utf-8")
    elif output:
        print(output)
    return 0


def _load_replay_source(source: Path, query: ReceiptQuery) -> tuple[dict[str, Any], list[ReceiptTrace]]:
    manifest_path: Path | None = None
    receipts_path: Path
    kind: str

    if source.is_dir():
        kind = "bundle"
        receipts_path = source / "receipts.jsonl"
        manifest_path = source / "manifest.json"
    elif source.name == "manifest.json":
        kind = "bundle"
        manifest_path = source
        receipts_path = source.parent / "receipts.jsonl"
    else:
        kind = "store"
        receipts_path = source

    if not receipts_path.exists():
        raise FileNotFoundError(f"Receipt source not found: {receipts_path}")

    manifest: dict[str, Any] | None = None
    if manifest_path is not None and manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    store = ReceiptStore(receipts_path)
    traces = store.build_traces(query)
    return {
        "kind": kind,
        "path": str(source),
        "receipts_path": str(receipts_path),
        "manifest": manifest,
    }, traces


def _render_replay(
    traces: list[ReceiptTrace],
    *,
    source_info: dict[str, Any],
    output_format: str,
    show_metadata: bool,
) -> str:
    if output_format == "json":
        return json.dumps(_build_replay_payload(traces, source_info=source_info), ensure_ascii=True, indent=2)
    if output_format == "html":
        return _render_replay_html(
            _build_replay_payload(traces, source_info=source_info),
            show_metadata=show_metadata,
        )
    return _render_replay_text(traces, source_info=source_info, show_metadata=show_metadata)


def _build_replay_payload(traces: list[ReceiptTrace], *, source_info: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": source_info,
        "traces": [
            {
                "trace_id": trace.trace_id,
                "started_at": trace.started_at,
                "ended_at": trace.ended_at,
                "step_count": len(trace.receipts),
                "action_hashes": trace.action_hashes,
                "events": [
                    {
                        "index": index,
                        "delta_seconds": _delta_seconds(trace, index - 1),
                        "created_at": payload.get("created_at"),
                        "status": payload.get("status"),
                        "decision": payload.get("decision"),
                        "policy_match": payload.get("policy_match"),
                        "approved_by": payload.get("approved_by"),
                        "approved_at": payload.get("approved_at"),
                        "action_hash": payload.get("action_hash"),
                        "action_summary": payload.get("action_summary"),
                        "result_preview": payload.get("result_preview"),
                        "error": payload.get("error"),
                    }
                    for index, payload in enumerate(trace.receipts, start=1)
                ],
            }
            for trace in traces
        ],
    }


def _render_replay_text(traces: list[ReceiptTrace], *, source_info: dict[str, Any], show_metadata: bool) -> str:
    if not traces:
        return "(no receipts matched)"

    manifest = source_info.get("manifest") or {}
    header = [
        f"Replay source: {source_info['kind']}",
        f"Source path: {source_info['path']}",
    ]
    if manifest.get("generated_at"):
        header.append(f"Bundle generated_at: {manifest['generated_at']}")
    if manifest.get("backend"):
        header.append(f"Bundle backend: {manifest['backend']}")

    blocks = ["\n".join(header)]
    for trace in traces:
        blocks.append(_render_trace_replay(trace, show_metadata=show_metadata))
    return "\n\n".join(blocks)


def _render_replay_html(payload: dict[str, Any], *, show_metadata: bool) -> str:
    traces: list[dict[str, Any]] = list(payload.get("traces", []))
    source = payload.get("source", {})
    manifest = source.get("manifest") or {}
    source_path = source.get("path") or "-"
    generated_at = manifest.get("generated_at") or "-"
    total_events = sum(len(trace.get("events", [])) for trace in traces)
    status_counts = _count_replay_field(traces, "status")
    decision_counts = _count_replay_field(traces, "decision")
    actor_values = _collect_replay_action_values(traces, "actor")
    surface_values = _collect_replay_action_values(traces, "surface")
    tool_values = _collect_replay_action_values(traces, "tool")
    risk_values = _collect_replay_risks(traces)

    summary_cards = [
        ("Source", str(source.get("kind", "-"))),
        ("Traces", str(len(traces))),
        ("Events", str(total_events)),
        ("Backend", str(manifest.get("backend") or "-")),
    ]
    summary_html = "".join(
        f'<div class="metric"><div class="metric-label">{escape(label)}</div><div class="metric-value">{escape(value)}</div></div>'
        for label, value in summary_cards
    )
    status_html = _render_html_count_list(status_counts)
    decision_html = _render_html_count_list(decision_counts)
    control_options = {
        "status": _render_html_filter_options(status_counts.keys()),
        "decision": _render_html_filter_options(decision_counts.keys()),
        "actor": _render_html_filter_options(actor_values),
        "surface": _render_html_filter_options(surface_values),
        "tool": _render_html_filter_options(tool_values),
        "risk": _render_html_filter_options(risk_values),
    }
    traces_html = "".join(
        _render_trace_html(trace, show_metadata=show_metadata)
        for trace in traces
    ) or '<section class="trace-card empty"><p>No events matched.</p></section>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DualKey Replay Viewer</title>
  <style>
    :root {{
      --bg: #f3efe6;
      --paper: #fffaf0;
      --ink: #1f2430;
      --muted: #5b6574;
      --line: #d6ccbb;
      --accent: #b85c38;
      --accent-soft: #f4d7c8;
      --success: #2f6f4f;
      --warning: #8a5a00;
      --danger: #9b2c2c;
      --shadow: 0 16px 40px rgba(31, 36, 48, 0.08);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Iowan Old Style", "Palatino Linotype", "Book Antiqua", Georgia, serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(184, 92, 56, 0.08), transparent 28%),
        linear-gradient(180deg, #f7f2e8 0%, var(--bg) 100%);
    }}
    .shell {{
      max-width: 1120px;
      margin: 0 auto;
      padding: 40px 20px 64px;
    }}
    .hero {{
      background: linear-gradient(135deg, rgba(184, 92, 56, 0.16), rgba(255, 250, 240, 0.92));
      border: 1px solid rgba(184, 92, 56, 0.18);
      border-radius: 28px;
      padding: 28px;
      box-shadow: var(--shadow);
    }}
    h1, h2, h3 {{
      margin: 0;
      font-weight: 700;
      letter-spacing: 0.01em;
    }}
    h1 {{ font-size: 2.3rem; }}
    h2 {{ font-size: 1.2rem; margin-bottom: 14px; }}
    h3 {{ font-size: 1rem; }}
    .hero-meta {{
      margin-top: 18px;
      display: grid;
      gap: 8px;
      color: var(--muted);
      font-size: 0.98rem;
    }}
    .metrics {{
      margin-top: 24px;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 14px;
    }}
    .metric, .panel, .trace-card, .event {{
      background: rgba(255, 250, 240, 0.86);
      border: 1px solid var(--line);
      border-radius: 20px;
      box-shadow: var(--shadow);
    }}
    .metric {{
      padding: 16px 18px;
    }}
    .metric-label {{
      color: var(--muted);
      font-size: 0.82rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}
    .metric-value {{
      margin-top: 8px;
      font-size: 1.5rem;
    }}
    .panels {{
      margin-top: 22px;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 16px;
    }}
    .panel {{
      padding: 18px 20px;
    }}
    .panel ul {{
      list-style: none;
      padding: 0;
      margin: 0;
      display: grid;
      gap: 10px;
    }}
    .panel li {{
      display: flex;
      justify-content: space-between;
      gap: 16px;
      color: var(--muted);
    }}
    .controls {{
      margin-top: 22px;
      padding: 18px 20px;
    }}
    .controls-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 12px;
    }}
    .control-field {{
      display: grid;
      gap: 6px;
    }}
    .control-field label,
    .control-check {{
      color: var(--muted);
      font-size: 0.82rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}
    .control-field input,
    .control-field select {{
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 12px;
      background: rgba(255, 250, 240, 0.95);
      color: var(--ink);
      padding: 10px 12px;
      font: inherit;
    }}
    .control-row {{
      margin-top: 14px;
      display: flex;
      flex-wrap: wrap;
      gap: 10px 14px;
      align-items: center;
      justify-content: space-between;
    }}
    .control-actions {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
    }}
    .control-actions button {{
      border: 1px solid rgba(184, 92, 56, 0.26);
      border-radius: 999px;
      background: rgba(184, 92, 56, 0.08);
      color: var(--accent);
      padding: 8px 14px;
      font: inherit;
      cursor: pointer;
    }}
    .control-check {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
    }}
    .control-check input {{
      accent-color: var(--accent);
    }}
    .viewer-summary {{
      color: var(--muted);
      font-size: 0.92rem;
    }}
    .trace-list {{
      margin-top: 26px;
      display: grid;
      gap: 22px;
    }}
    .trace-card {{
      padding: 0;
    }}
    .trace-card[hidden], .event[hidden] {{
      display: none !important;
    }}
    .trace-details {{
      margin: 0;
    }}
    .trace-summary {{
      list-style: none;
      cursor: pointer;
      padding: 22px;
    }}
    .trace-summary::-webkit-details-marker {{
      display: none;
    }}
    .trace-summary::marker {{
      display: none;
    }}
    .trace-head {{
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      gap: 16px;
      align-items: start;
      margin: 0;
    }}
    .trace-meta {{
      color: var(--muted);
      display: grid;
      gap: 6px;
      font-size: 0.94rem;
    }}
    .chips {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 8px;
    }}
    .chip {{
      background: var(--accent-soft);
      color: var(--accent);
      border-radius: 999px;
      padding: 5px 10px;
      font-size: 0.82rem;
    }}
    .trace-body {{
      padding: 0 22px 22px;
    }}
    .trace-toggle {{
      color: var(--muted);
      font-size: 0.84rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}
    .events {{
      display: grid;
      gap: 14px;
    }}
    .event {{
      padding: 16px 18px;
    }}
    .detail-block {{
      margin: 0;
      border: 1px solid rgba(31, 36, 48, 0.08);
      border-radius: 14px;
      background: rgba(255, 250, 240, 0.7);
      padding: 10px 12px 12px;
    }}
    .detail-block summary {{
      cursor: pointer;
      color: var(--muted);
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 10px;
    }}
    .detail-block[open] summary {{
      margin-bottom: 10px;
    }}
    body.metadata-hidden .metadata-block {{
      display: none !important;
    }}
    .event-top {{
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 10px 12px;
      margin-bottom: 12px;
    }}
    .event-index {{
      font-size: 0.82rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
    }}
    .event-time {{
      font-weight: 700;
    }}
    .pill {{
      border-radius: 999px;
      padding: 4px 10px;
      font-size: 0.8rem;
      border: 1px solid transparent;
    }}
    .pill.status-executed {{ background: rgba(47, 111, 79, 0.12); color: var(--success); border-color: rgba(47, 111, 79, 0.16); }}
    .pill.status-waiting {{ background: rgba(138, 90, 0, 0.12); color: var(--warning); border-color: rgba(138, 90, 0, 0.16); }}
    .pill.status-blocked {{ background: rgba(155, 44, 44, 0.12); color: var(--danger); border-color: rgba(155, 44, 44, 0.16); }}
    .pill.policy {{ background: rgba(31, 36, 48, 0.06); color: var(--ink); border-color: rgba(31, 36, 48, 0.08); }}
    .event-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 10px 14px;
      color: var(--muted);
      font-size: 0.94rem;
    }}
    .label {{
      display: block;
      margin-bottom: 4px;
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
    }}
    code {{
      font-family: "SFMono-Regular", "JetBrains Mono", "Fira Code", Consolas, monospace;
      background: rgba(31, 36, 48, 0.05);
      border-radius: 8px;
      padding: 2px 6px;
      word-break: break-word;
    }}
    pre {{
      margin: 0;
      padding: 12px 14px;
      background: rgba(31, 36, 48, 0.05);
      border-radius: 14px;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-word;
      font-family: "SFMono-Regular", "JetBrains Mono", "Fira Code", Consolas, monospace;
      font-size: 0.88rem;
      line-height: 1.45;
    }}
	    @media (max-width: 720px) {{
	      .shell {{ padding: 24px 14px 48px; }}
	      .hero {{ padding: 22px 18px; border-radius: 22px; }}
	      h1 {{ font-size: 1.85rem; }}
	      .trace-summary {{ padding: 18px; }}
	      .trace-body {{ padding: 0 18px 18px; }}
	    }}
  </style>
</head>
<body>
  <main class="shell">
    <section class="hero">
      <h1>DualKey Replay Viewer</h1>
      <div class="hero-meta">
        <div><strong>Source:</strong> {escape(str(source.get("kind", "-")))}</div>
        <div><strong>Path:</strong> <code>{escape(str(source_path))}</code></div>
        <div><strong>Generated:</strong> {escape(str(generated_at))}</div>
      </div>
      <div class="metrics">{summary_html}</div>
    </section>
    <section class="panels">
      <section class="panel">
        <h2>Status Breakdown</h2>
        {status_html}
      </section>
      <section class="panel">
        <h2>Decision Breakdown</h2>
        {decision_html}
      </section>
    </section>
    <section class="panel controls">
      <h2>Filters &amp; Folding</h2>
      <div class="controls-grid">
        <div class="control-field">
          <label for="filter-search">Search</label>
          <input id="filter-search" type="search" placeholder="trace id, target, metadata, result">
        </div>
        <div class="control-field">
          <label for="filter-status">Status</label>
          <select id="filter-status">{control_options["status"]}</select>
        </div>
        <div class="control-field">
          <label for="filter-decision">Decision</label>
          <select id="filter-decision">{control_options["decision"]}</select>
        </div>
        <div class="control-field">
          <label for="filter-actor">Actor</label>
          <select id="filter-actor">{control_options["actor"]}</select>
        </div>
        <div class="control-field">
          <label for="filter-surface">Surface</label>
          <select id="filter-surface">{control_options["surface"]}</select>
        </div>
        <div class="control-field">
          <label for="filter-tool">Tool</label>
          <select id="filter-tool">{control_options["tool"]}</select>
        </div>
        <div class="control-field">
          <label for="filter-risk">Risk</label>
          <select id="filter-risk">{control_options["risk"]}</select>
        </div>
      </div>
      <div class="control-row">
        <div class="control-actions">
          <button id="reset-filters" type="button">Reset filters</button>
          <button id="expand-traces" type="button">Expand all traces</button>
          <button id="collapse-traces" type="button">Collapse all traces</button>
        </div>
        <label class="control-check" for="toggle-metadata">
          <input id="toggle-metadata" type="checkbox" {"checked" if show_metadata else ""}>
          Show metadata blocks
        </label>
        <div class="viewer-summary" id="viewer-summary">Loading viewer state…</div>
      </div>
    </section>
    <section class="trace-list">
      {traces_html}
    </section>
  </main>
  <script>
    (() => {{
      const controls = {{
        search: document.getElementById("filter-search"),
        status: document.getElementById("filter-status"),
        decision: document.getElementById("filter-decision"),
        actor: document.getElementById("filter-actor"),
        surface: document.getElementById("filter-surface"),
        tool: document.getElementById("filter-tool"),
        risk: document.getElementById("filter-risk"),
        metadataToggle: document.getElementById("toggle-metadata"),
        summary: document.getElementById("viewer-summary"),
      }};
      const resetButton = document.getElementById("reset-filters");
      const expandButton = document.getElementById("expand-traces");
      const collapseButton = document.getElementById("collapse-traces");
      const traceCards = Array.from(document.querySelectorAll(".trace-card"));

      const normalize = (value) => String(value || "").toLowerCase();
      const updateMetadataMode = () => {{
        document.body.classList.toggle("metadata-hidden", !controls.metadataToggle.checked);
      }};

      const matchesEvent = (eventNode) => {{
        const data = eventNode.dataset;
        if (controls.status.value && data.status !== controls.status.value) return false;
        if (controls.decision.value && data.decision !== controls.decision.value) return false;
        if (controls.actor.value && data.actor !== controls.actor.value) return false;
        if (controls.surface.value && data.surface !== controls.surface.value) return false;
        if (controls.tool.value && data.tool !== controls.tool.value) return false;
        if (controls.risk.value) {{
          const risks = (data.risk || "").split("|").filter(Boolean);
          if (!risks.includes(controls.risk.value)) return false;
        }}
        const search = normalize(controls.search.value);
        if (search) {{
          const traceData = eventNode.closest(".trace-card")?.dataset || {{}};
          const haystack = `${{data.search || ""}} ${{traceData.search || ""}}`;
          if (!normalize(haystack).includes(search)) return false;
        }}
        return true;
      }};

      const applyFilters = () => {{
        updateMetadataMode();
        let visibleTraces = 0;
        let visibleEvents = 0;
        let totalEvents = 0;
        for (const traceCard of traceCards) {{
          const events = Array.from(traceCard.querySelectorAll(".event"));
          let traceVisible = 0;
          totalEvents += events.length;
          for (const eventNode of events) {{
            const visible = matchesEvent(eventNode);
            eventNode.hidden = !visible;
            if (visible) traceVisible += 1;
          }}
          traceCard.hidden = traceVisible === 0;
          const countNode = traceCard.querySelector("[data-visible-events]");
          if (countNode) {{
            countNode.textContent = `${{traceVisible}}/${{events.length}} visible`;
          }}
          if (traceVisible > 0) {{
            visibleTraces += 1;
            visibleEvents += traceVisible;
          }}
        }}
        controls.summary.textContent = `${{visibleEvents}}/${{totalEvents}} events visible across ${{visibleTraces}}/${{traceCards.length}} traces`;
      }};

      for (const node of [controls.search, controls.status, controls.decision, controls.actor, controls.surface, controls.tool, controls.risk]) {{
        node.addEventListener(node === controls.search ? "input" : "change", applyFilters);
      }}
      controls.metadataToggle.addEventListener("change", updateMetadataMode);
      resetButton.addEventListener("click", () => {{
        controls.search.value = "";
        controls.status.value = "";
        controls.decision.value = "";
        controls.actor.value = "";
        controls.surface.value = "";
        controls.tool.value = "";
        controls.risk.value = "";
        controls.metadataToggle.checked = {str(show_metadata).lower()};
        applyFilters();
      }});
      expandButton.addEventListener("click", () => {{
        for (const details of document.querySelectorAll(".trace-details")) {{
          details.open = true;
        }}
      }});
      collapseButton.addEventListener("click", () => {{
        for (const details of document.querySelectorAll(".trace-details")) {{
          details.open = false;
        }}
      }});

      applyFilters();
    }})();
  </script>
</body>
</html>
"""
    return html


def _render_trace_html(trace: dict[str, Any], *, show_metadata: bool) -> str:
    trace_id = str(trace.get("trace_id", "-"))
    action_hashes = [str(action_hash) for action_hash in trace.get("action_hashes", [])]
    chips = "".join(
        f'<span class="chip">{escape(action_hash)}</span>'
        for action_hash in action_hashes
    )
    events_html = "".join(
        _render_event_html(event, show_metadata=show_metadata)
        for event in trace.get("events", [])
    )
    return f"""
<section
  class="trace-card"
  data-trace-id="{escape(trace_id)}"
  data-action-hashes="{escape(' '.join(action_hashes))}"
  data-search="{escape(' '.join([trace_id, *action_hashes]))}"
>
  <details class="trace-details" open>
    <summary class="trace-summary">
      <div class="trace-head">
        <div>
          <h2>Trace {escape(trace_id)}</h2>
          <div class="chips">{chips}</div>
        </div>
        <div class="trace-meta">
          <div><strong>Started:</strong> {escape(str(trace.get('started_at') or '-'))}</div>
          <div><strong>Ended:</strong> {escape(str(trace.get('ended_at') or '-'))}</div>
          <div><strong>Steps:</strong> {escape(str(trace.get('step_count', 0)))}</div>
          <div><strong>Visible:</strong> <span data-visible-events>{escape(str(trace.get('step_count', 0)))}/{escape(str(trace.get('step_count', 0)))}</span></div>
          <div class="trace-toggle">Toggle trace</div>
        </div>
      </div>
    </summary>
    <div class="trace-body">
      <div class="events">{events_html}</div>
    </div>
  </details>
</section>
"""


def _render_event_html(event: dict[str, Any], *, show_metadata: bool) -> str:
    summary = event.get("action_summary") if isinstance(event.get("action_summary"), dict) else {}
    status = str(event.get("status") or "unknown")
    decision = str(event.get("decision") or "-")
    status_class = f"status-{escape(status)}"
    actor = str(summary.get("actor") or "")
    surface = str(summary.get("surface") or "")
    tool = str(summary.get("tool") or "")
    intent = str(summary.get("intent") or "")
    target = str(summary.get("target") or "")
    risk_values = [str(item) for item in summary.get("risk", [])] if isinstance(summary.get("risk"), list) else []
    context = _format_action_overlay(summary) if summary else ""
    metadata = _format_action_metadata_overlay(summary) if show_metadata and summary else ""
    metadata_html = ""
    if metadata:
        metadata_html = (
            '<details class="detail-block metadata-block" open>'
            '<summary>Metadata</summary>'
            f"<pre>{escape(metadata)}</pre>"
            "</details>"
        )
    error_or_result = ""
    if event.get("error"):
        error_or_result = (
            '<details class="detail-block" open>'
            "<summary>Error</summary>"
            f"<pre>{escape(str(event['error']))}</pre>"
            "</details>"
        )
    elif event.get("result_preview"):
        error_or_result = (
            '<details class="detail-block" open>'
            "<summary>Result</summary>"
            f"<pre>{escape(str(event['result_preview']))}</pre>"
            "</details>"
        )
    approved_by = event.get("approved_by") or "-"
    approved_at = event.get("approved_at") or "-"
    search_parts = [
        str(event.get("created_at") or ""),
        status,
        decision,
        str(event.get("policy_match") or ""),
        str(event.get("action_hash") or ""),
        context,
        metadata,
        str(event.get("error") or ""),
        str(event.get("result_preview") or ""),
    ]
    search_text = " ".join(part for part in search_parts if part)
    return f"""
<article
  class="event"
  data-status="{escape(status)}"
  data-decision="{escape(decision)}"
  data-actor="{escape(actor)}"
  data-surface="{escape(surface)}"
  data-tool="{escape(tool)}"
  data-intent="{escape(intent)}"
  data-risk="{escape('|'.join(risk_values))}"
  data-target="{escape(target)}"
  data-search="{escape(search_text)}"
>
  <div class="event-top">
    <span class="event-index">Step {escape(str(event.get('index', '-')))}</span>
    <span class="event-time">{escape(str(event.get('created_at') or '-'))}</span>
    <span class="pill {status_class}">{escape(status)}</span>
    <span class="pill">{escape(decision)}</span>
    <span class="pill policy">{escape(str(event.get('policy_match') or '-'))}</span>
    <span class="pill">+{escape(f"{float(event.get('delta_seconds', 0.0)):.1f}")}s</span>
  </div>
  <div class="event-grid">
    <div><span class="label">Context</span><pre>{escape(context or '-')}</pre></div>
    <div><span class="label">Action Hash</span><pre>{escape(str(event.get('action_hash') or '-'))}</pre></div>
    <div><span class="label">Approved By</span><pre>{escape(str(approved_by))}</pre></div>
    <div><span class="label">Approved At</span><pre>{escape(str(approved_at))}</pre></div>
    {metadata_html}
    {error_or_result}
  </div>
</article>
"""


def _count_replay_field(traces: list[dict[str, Any]], field_name: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for trace in traces:
        for event in trace.get("events", []):
            key = str(event.get(field_name) or "(none)")
            counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def _render_html_count_list(counts: dict[str, int]) -> str:
    if not counts:
        return "<p>(none)</p>"
    items = "".join(
        f"<li><span>{escape(key)}</span><strong>{escape(str(value))}</strong></li>"
        for key, value in counts.items()
    )
    return f"<ul>{items}</ul>"


def _render_html_filter_options(values: Any) -> str:
    options = ['<option value="">All</option>']
    for value in values:
        options.append(f'<option value="{escape(str(value))}">{escape(str(value))}</option>')
    return "".join(options)


def _collect_replay_action_values(traces: list[dict[str, Any]], field_name: str) -> list[str]:
    values: set[str] = set()
    for trace in traces:
        for event in trace.get("events", []):
            summary = event.get("action_summary")
            if not isinstance(summary, dict):
                continue
            value = summary.get(field_name)
            if value:
                values.add(str(value))
    return sorted(values)


def _collect_replay_risks(traces: list[dict[str, Any]]) -> list[str]:
    values: set[str] = set()
    for trace in traces:
        for event in trace.get("events", []):
            summary = event.get("action_summary")
            if not isinstance(summary, dict):
                continue
            risk_values = summary.get("risk")
            if not isinstance(risk_values, list):
                continue
            values.update(str(item) for item in risk_values if item)
    return sorted(values)


def _render_trace_replay(trace: ReceiptTrace, *, show_metadata: bool) -> str:
    lines = [
        f"trace_id: {trace.trace_id}",
        f"started_at: {trace.started_at or '-'}",
        f"ended_at: {trace.ended_at or '-'}",
        f"steps: {len(trace.receipts)}",
    ]
    if trace.action_hashes:
        lines.append(f"action_hashes: {', '.join(trace.action_hashes)}")
    for index, payload in enumerate(trace.receipts, start=1):
        delta = _delta_seconds(trace, index - 1)
        line = (
            f"{index}. +{delta:.1f}s "
            f"{payload.get('created_at', '-')} "
            f"{payload.get('status', '-')} "
            f"{payload.get('decision', '-')}"
        )
        if payload.get("policy_match"):
            line += f" policy={payload['policy_match']}"
        lines.append(line)
        action_summary = payload.get("action_summary")
        if isinstance(action_summary, dict):
            overlay = _format_action_overlay(action_summary)
            if overlay:
                lines.append(f"   context: {overlay}")
            metadata_overlay = _format_action_metadata_overlay(action_summary) if show_metadata else ""
            if metadata_overlay:
                lines.append(f"   metadata: {metadata_overlay}")
        action_hash = payload.get("action_hash")
        if action_hash:
            lines.append(f"   action_hash: {action_hash}")
        if payload.get("approved_by"):
            lines.append(f"   approved_by: {payload['approved_by']}")
        if payload.get("approved_at"):
            lines.append(f"   approved_at: {payload['approved_at']}")
        if payload.get("error"):
            lines.append(f"   error: {payload['error']}")
        elif payload.get("result_preview"):
            lines.append(f"   result: {payload['result_preview']}")
    return "\n".join(lines)


def _filter_traces(
    traces: list[ReceiptTrace],
    *,
    actor: str | None,
    surface: str | None,
    tool: str | None,
    intent: str | None,
    risk: str | None,
    target_contains: str | None,
    metadata_path: str | None,
    metadata_contains: str | None,
) -> list[ReceiptTrace]:
    if not any([actor, surface, tool, intent, risk, target_contains, metadata_path, metadata_contains]):
        return traces

    filtered: list[ReceiptTrace] = []
    for trace in traces:
        receipts = [
            payload
            for payload in trace.receipts
            if _matches_action_filter(
                payload.get("action_summary"),
                actor=actor,
                surface=surface,
                tool=tool,
                intent=intent,
                risk=risk,
                target_contains=target_contains,
                metadata_path=metadata_path,
                metadata_contains=metadata_contains,
            )
        ]
        if receipts:
            filtered.append(
                ReceiptTrace(
                    trace_id=trace.trace_id,
                    started_at=str(receipts[0].get("created_at")) if receipts else None,
                    ended_at=str(receipts[-1].get("created_at")) if receipts else None,
                    receipts=receipts,
                    action_hashes=list(
                        dict.fromkeys(
                            str(payload.get("action_hash"))
                            for payload in receipts
                            if payload.get("action_hash")
                        )
                    ),
                )
            )
    return filtered


def _matches_action_filter(
    action_summary: Any,
    *,
    actor: str | None,
    surface: str | None,
    tool: str | None,
    intent: str | None,
    risk: str | None,
    target_contains: str | None,
    metadata_path: str | None,
    metadata_contains: str | None,
) -> bool:
    if not isinstance(action_summary, dict):
        return False
    if actor is not None and str(action_summary.get("actor")) != actor:
        return False
    if surface is not None and str(action_summary.get("surface")) != surface:
        return False
    if tool is not None and str(action_summary.get("tool")) != tool:
        return False
    if intent is not None and str(action_summary.get("intent")) != intent:
        return False
    if risk is not None:
        risk_values = action_summary.get("risk")
        if not isinstance(risk_values, list) or risk not in [str(item) for item in risk_values]:
            return False
    if target_contains is not None:
        target = action_summary.get("target")
        if target is None or target_contains not in str(target):
            return False
    if metadata_path is not None or metadata_contains is not None:
        metadata = action_summary.get("metadata")
        value = _resolve_metadata_value(metadata, metadata_path)
        if metadata_path is not None and value is None:
            return False
        if metadata_contains is not None:
            haystack = _stringify_metadata_value(value if metadata_path is not None else metadata)
            if metadata_contains not in haystack:
                return False
    return True


def _format_action_overlay(action_summary: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("actor", "surface", "tool", "intent", "target"):
        value = action_summary.get(key)
        if value:
            parts.append(f"{key}={value}")
    risk_values = action_summary.get("risk")
    if isinstance(risk_values, list) and risk_values:
        parts.append("risk=" + ",".join(str(item) for item in risk_values))
    return " ".join(parts)


def _format_action_metadata_overlay(action_summary: dict[str, Any]) -> str:
    metadata = action_summary.get("metadata")
    if not isinstance(metadata, dict) or not metadata:
        return ""
    return _stringify_metadata_value(metadata)


def _resolve_metadata_value(metadata: Any, metadata_path: str | None) -> Any:
    if metadata_path is None:
        return metadata
    if not isinstance(metadata, dict):
        return None
    value: Any = metadata
    for part in metadata_path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _stringify_metadata_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        items = [f"{key}={_stringify_metadata_value(item)}" for key, item in value.items()]
        return "{" + ", ".join(items) + "}"
    if isinstance(value, list):
        return "[" + ", ".join(_stringify_metadata_value(item) for item in value) + "]"
    return str(value)


def _delta_seconds(trace: ReceiptTrace, index: int) -> float:
    payload = trace.receipts[index]
    current = _parse_timestamp(payload.get("created_at"))
    if current is None:
        return 0.0
    if index == 0:
        baseline = _parse_timestamp(trace.started_at)
        return 0.0 if baseline is None else max((current - baseline).total_seconds(), 0.0)
    previous = _parse_timestamp(trace.receipts[index - 1].get("created_at"))
    if previous is None:
        return 0.0
    return max((current - previous).total_seconds(), 0.0)


def _parse_timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be >= 0")
    return parsed


if __name__ == "__main__":
    raise SystemExit(main())
