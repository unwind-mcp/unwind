"""UNWIND Export Engine — JSON, JSONL, and HTML report generation.

Export formats:
- JSON: Full structured export with metadata
- JSONL: One event per line (for log ingestion pipelines)
- HTML: Self-contained printable audit report
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from ..config import UnwindConfig
from ..recorder.event_store import EventStore
from ..dashboard.away_mode import generate_away_summary


def export_json(
    store: EventStore,
    output_path: Path,
    since: Optional[float] = None,
    session_id: Optional[str] = None,
) -> int:
    """Export events as structured JSON.

    Returns the number of events exported.
    """
    events = store.query_events(since=since, session_id=session_id, limit=100000)
    events_chrono = list(reversed(events))

    valid, chain_error = store.verify_chain()

    export = {
        "unwind_version": "0.1.0",
        "exported_at": datetime.now().isoformat(),
        "event_count": len(events_chrono),
        "chain_valid": valid,
        "chain_error": chain_error,
        "filters": {
            "since": datetime.fromtimestamp(since).isoformat() if since else None,
            "session_id": session_id,
        },
        "events": events_chrono,
    }

    with open(output_path, "w") as f:
        json.dump(export, f, indent=2, default=str)

    return len(events_chrono)


def export_jsonl(
    store: EventStore,
    output_path: Path,
    since: Optional[float] = None,
    session_id: Optional[str] = None,
) -> int:
    """Export events as JSONL (one JSON object per line).

    Ideal for log ingestion into Splunk, Datadog, ELK, etc.
    Returns the number of events exported.
    """
    events = store.query_events(since=since, session_id=session_id, limit=100000)
    events_chrono = list(reversed(events))

    with open(output_path, "w") as f:
        for event in events_chrono:
            f.write(json.dumps(event, default=str) + "\n")

    return len(events_chrono)


def export_html_report(
    store: EventStore,
    output_path: Path,
    since: Optional[float] = None,
    session_id: Optional[str] = None,
    title: str = "UNWIND Audit Report",
) -> int:
    """Export a self-contained HTML audit report.

    Generates a printable, professional report with:
    - Summary statistics
    - Trust state history
    - Event timeline
    - Chain integrity status

    Returns the number of events in the report.
    """
    events = store.query_events(since=since, session_id=session_id, limit=100000)
    events_chrono = list(reversed(events))
    valid, chain_error = store.verify_chain()

    # Generate summary
    summary_since = since or (events_chrono[0]["timestamp"] if events_chrono else time.time())
    summary = generate_away_summary(store, summary_since)

    # Build HTML
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    period_start = datetime.fromtimestamp(summary_since).strftime("%Y-%m-%d %H:%M") if since else "All time"
    period_end = now

    trust_colors = {"green": "#3fb950", "amber": "#d29922", "red": "#f85149"}
    trust_color = trust_colors.get(summary.trust_state, "#8b949e")

    # Event rows
    event_rows = []
    for e in events_chrono:
        ts = datetime.fromtimestamp(e["timestamp"]).strftime("%H:%M:%S")
        status_class = ""
        if e.get("status") == "blocked":
            status_class = "blocked"
        elif e.get("ghost_mode"):
            status_class = "ghost"
        elif e.get("trust_state") == "red":
            status_class = "red"
        elif e.get("trust_state") == "amber":
            status_class = "amber"

        target = e.get("target", "")
        if target and len(target) > 60:
            target = "..." + target[-57:]

        event_rows.append(f"""
            <tr class="{status_class}">
                <td class="mono">{ts}</td>
                <td>{e['event_id']}</td>
                <td><strong>{e['tool']}</strong></td>
                <td>{e.get('tool_class', '')}</td>
                <td class="target">{target}</td>
                <td>{e.get('status', '')}</td>
                <td>{e.get('trust_state', '')}</td>
                <td>{'Yes' if e.get('ghost_mode') else ''}</td>
            </tr>""")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
               color: #1a1a2e; background: #fff; padding: 40px; max-width: 1100px; margin: 0 auto; }}
        h1 {{ font-size: 24px; margin-bottom: 4px; }}
        .subtitle {{ color: #666; font-size: 13px; margin-bottom: 24px; }}
        .section {{ margin-bottom: 32px; }}
        .section h2 {{ font-size: 16px; border-bottom: 2px solid #e1e4e8; padding-bottom: 6px; margin-bottom: 12px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }}
        .stat-card {{ background: #f6f8fa; border-radius: 6px; padding: 16px; text-align: center; }}
        .stat-card .val {{ font-size: 28px; font-weight: 700; }}
        .stat-card .lbl {{ font-size: 11px; color: #666; text-transform: uppercase; letter-spacing: 1px; }}
        .trust-badge {{ display: inline-block; padding: 4px 12px; border-radius: 12px; font-weight: 600;
                        font-size: 13px; color: white; background: {trust_color}; }}
        .chain-badge {{ display: inline-block; padding: 4px 12px; border-radius: 12px; font-weight: 600;
                        font-size: 13px; color: white;
                        background: {'#3fb950' if valid else '#f85149'}; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
        th {{ background: #f6f8fa; text-align: left; padding: 8px; border-bottom: 2px solid #e1e4e8;
              font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }}
        td {{ padding: 6px 8px; border-bottom: 1px solid #eee; }}
        .mono {{ font-family: monospace; }}
        .target {{ max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
        tr.blocked {{ background: rgba(248,81,73,0.08); }}
        tr.ghost {{ background: rgba(137,87,229,0.08); }}
        tr.red {{ background: rgba(248,81,73,0.05); }}
        tr.amber {{ background: rgba(210,153,34,0.05); }}
        .footer {{ margin-top: 32px; padding-top: 16px; border-top: 1px solid #e1e4e8;
                   font-size: 11px; color: #999; }}
        @media print {{ body {{ padding: 20px; }} .stats-grid {{ grid-template-columns: repeat(4, 1fr); }} }}
    </style>
</head>
<body>
    <h1>{title}</h1>
    <div class="subtitle">Generated {now} &mdash; Period: {period_start} to {period_end}</div>

    <div class="section">
        <h2>Summary</h2>
        <div class="stats-grid">
            <div class="stat-card"><div class="val">{summary.total_actions}</div><div class="lbl">Total Actions</div></div>
            <div class="stat-card"><div class="val">{summary.blocked_actions}</div><div class="lbl">Blocked</div></div>
            <div class="stat-card"><div class="val">{summary.ghost_actions}</div><div class="lbl">Ghost Mode</div></div>
            <div class="stat-card"><div class="val">{summary.taint_events}</div><div class="lbl">Taint Events</div></div>
        </div>
        <div style="margin-bottom:8px;">
            Trust State: <span class="trust-badge">{summary.trust_state.upper()}</span>
            &nbsp;&nbsp;
            Chain Integrity: <span class="chain-badge">{'VALID' if valid else 'BROKEN'}</span>
        </div>
        {f'<div style="color:#f85149;margin-top:8px;">Chain error: {chain_error}</div>' if chain_error else ''}
    </div>

    <div class="section">
        <h2>Activity Breakdown</h2>
        <div class="stats-grid">
            <div class="stat-card"><div class="val">{summary.emails_sent}</div><div class="lbl">Emails Sent</div></div>
            <div class="stat-card"><div class="val">{summary.messages_sent}</div><div class="lbl">Messages</div></div>
            <div class="stat-card"><div class="val">{summary.files_modified + summary.files_created}</div><div class="lbl">Files Changed</div></div>
            <div class="stat-card"><div class="val">{summary.web_searches}</div><div class="lbl">Web Searches</div></div>
        </div>
    </div>

    {f'''<div class="section">
        <h2>Items for Review ({len(summary.review_items)})</h2>
        {''.join(f'<div style="background:#fff3cd;border:1px solid #ffc107;border-radius:4px;padding:8px;margin:4px 0;font-size:13px;"><strong>{item["tool"]}</strong> &rarr; {item.get("target","")} &mdash; {item.get("reason","")}</div>' for item in summary.review_items)}
    </div>''' if summary.review_items else ''}

    <div class="section">
        <h2>Event Timeline ({len(events_chrono)} events)</h2>
        <table>
            <thead>
                <tr>
                    <th>Time</th><th>Event ID</th><th>Tool</th><th>Class</th>
                    <th>Target</th><th>Status</th><th>Trust</th><th>Ghost</th>
                </tr>
            </thead>
            <tbody>
                {''.join(event_rows)}
            </tbody>
        </table>
    </div>

    <div class="footer">
        UNWIND v0.1.0 &mdash; See Everything. Undo Anything. Test Anything Safely.
        &mdash; Report generated {now}
    </div>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)

    return len(events_chrono)
