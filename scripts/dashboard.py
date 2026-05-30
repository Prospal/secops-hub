"""Generate a self-contained HTML dashboard from findings.jsonl and out/cases/.

Usage:
  python scripts/dashboard.py [--out path/to/dashboard.html]

Via dispatch:
  dispatch.py "generate dashboard"
  dispatch.py "open dashboard"
  dispatch.py "show metrics"
"""

import argparse
import datetime as dt
import json
import pathlib
import sys

# Minutes a human analyst would spend doing this manually vs automated seconds
ROI_BASELINES = {
    "triage":          {"manual_min": 20,  "auto_sec": 30,  "label": "IOC Triage"},
    "cve_lookup":      {"manual_min": 10,  "auto_sec": 15,  "label": "CVE Lookup"},
    "detection_rule":  {"manual_min": 90,  "auto_sec": 45,  "label": "Detection Rule"},
    "log_scan":        {"manual_min": 30,  "auto_sec": 20,  "label": "Log Scan"},
    "pipeline":        {"manual_min": 20,  "auto_sec": 45,  "label": "Alert Pipeline"},
    "scan_assets":     {"manual_min": 15,  "auto_sec": 20,  "label": "Asset Scan"},
    "demo_logs":       {"manual_min":  5,  "auto_sec":  5,  "label": "Demo Logs"},
    "alert_simulator": {"manual_min":  5,  "auto_sec":  5,  "label": "Alert Simulator"},
    "evtx_to_jsonl":   {"manual_min": 10,  "auto_sec": 10,  "label": "EVTX Converter"},
}

ANALYST_HOURLY_RATE_USD = 65  # mid-market Tier-1 SOC analyst


def _skill_dir() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1]


def _journal_path() -> pathlib.Path:
    return _skill_dir() / "out" / "findings.jsonl"


def _cases_dir() -> pathlib.Path:
    return _skill_dir() / "out" / "cases"


def _load_entries() -> list[dict]:
    p = _journal_path()
    if not p.exists():
        return []
    items = []
    with p.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except Exception:
                pass
    return items


def _compute_roi(entries: list[dict]) -> dict:
    total_manual_min = 0.0
    total_auto_sec = 0.0
    by_cap: dict[str, int] = {}

    for e in entries:
        cap = e.get("capability", "triage")
        by_cap[cap] = by_cap.get(cap, 0) + 1
        b = ROI_BASELINES.get(cap, {"manual_min": 10, "auto_sec": 30})
        total_manual_min += b["manual_min"]
        total_auto_sec += b["auto_sec"]

    saved_min = total_manual_min - (total_auto_sec / 60)
    saved_hours = saved_min / 60
    dollar_saved = saved_hours * ANALYST_HOURLY_RATE_USD

    return {
        "total_queries": len(entries),
        "total_manual_min": total_manual_min,
        "total_auto_sec": total_auto_sec,
        "saved_min": max(0, saved_min),
        "saved_hours": max(0, saved_hours),
        "dollar_saved": max(0, dollar_saved),
        "by_cap": by_cap,
    }


def _severity_counts(entries: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for e in entries:
        sev = (e.get("result") or {}).get("severity", "Info")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _decision_counts(cases_dir: pathlib.Path) -> dict[str, int]:
    counts = {"escalate": 0, "review": 0, "suppress": 0}
    for md in cases_dir.glob("case-*.md"):
        text = md.read_text(encoding="utf-8", errors="ignore")
        for line in text.splitlines():
            if line.startswith("**Decision:**"):
                dl = line.lower()
                if "escalate" in dl:
                    counts["escalate"] += 1
                elif "review" in dl:
                    counts["review"] += 1
                elif "suppress" in dl:
                    counts["suppress"] += 1
                break
    return counts


def _recent_findings(entries: list[dict], n: int = 10) -> list[dict]:
    out = []
    for e in reversed(entries[-n:]):
        res = e.get("result") or {}
        out.append({
            "ts": e.get("ts", ""),
            "cap": e.get("capability", ""),
            "input": (e.get("input") or "")[:60],
            "severity": res.get("severity", "Info"),
            "mitre": res.get("mitre", "N/A"),
        })
    return out


def _sev_color(sev: str) -> str:
    return {
        "Critical": "#e53e3e",
        "High":     "#dd6b20",
        "Medium":   "#d69e2e",
        "Low":      "#38a169",
        "Info":     "#3182ce",
    }.get(sev, "#718096")


def _bar(value: int, total: int, color: str) -> str:
    pct = int((value / total * 100)) if total else 0
    return (
        f'<div style="display:flex;align-items:center;gap:8px">'
        f'<div style="width:{max(pct,2)}%;height:14px;background:{color};border-radius:3px;min-width:4px"></div>'
        f'<span style="font-size:12px;color:#a0aec0">{value} ({pct}%)</span>'
        f'</div>'
    )


def generate_html(entries: list[dict]) -> str:
    roi = _compute_roi(entries)
    sev_counts = _severity_counts(entries)
    decision_counts = _decision_counts(_cases_dir())
    recent = _recent_findings(entries)
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    total = roi["total_queries"] or 1

    # ROI table rows
    roi_rows = ""
    for cap, b in ROI_BASELINES.items():
        count = roi["by_cap"].get(cap, 0)
        if count == 0:
            continue
        saved = (b["manual_min"] * count) - (b["auto_sec"] * count / 60)
        roi_rows += (
            f"<tr><td>{b['label']}</td><td>{count}</td>"
            f"<td>{b['manual_min']} min</td><td>{b['auto_sec']} sec</td>"
            f"<td><strong>{saved:.1f} min</strong></td></tr>\n"
        )

    # severity rows
    sev_rows = ""
    for sev, count in sev_counts.items():
        color = _sev_color(sev)
        bar_html = _bar(count, total, color)
        sev_rows += (
            f'<tr><td><span style="color:{color};font-weight:600">{sev}</span></td>'
            f'<td>{bar_html}</td></tr>\n'
        )

    # recent findings rows
    recent_rows = ""
    for f in recent:
        color = _sev_color(f["severity"])
        cap_label = ROI_BASELINES.get(f["cap"], {}).get("label", f["cap"])
        recent_rows += (
            f'<tr><td style="color:#a0aec0;font-size:11px">{f["ts"][:19].replace("T"," ")}</td>'
            f'<td style="font-size:12px">{cap_label}</td>'
            f'<td style="font-size:12px;max-width:220px;overflow:hidden;white-space:nowrap;text-overflow:ellipsis">{f["input"]}</td>'
            f'<td><span style="color:{color};font-weight:600;font-size:12px">{f["severity"]}</span></td>'
            f'<td style="font-size:11px;color:#a0aec0">{f["mitre"]}</td></tr>\n'
        )

    cases_total = sum(decision_counts.values())

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecOps Hub — Dashboard</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0f1117; color: #e2e8f0; min-height: 100vh; }}
  .topbar {{ background: #1a1d27; border-bottom: 1px solid #2d3748; padding: 16px 32px; display: flex; align-items: center; justify-content: space-between; }}
  .logo {{ font-size: 18px; font-weight: 700; color: #68d391; letter-spacing: 0.5px; }}
  .logo span {{ color: #a0aec0; font-weight: 400; font-size: 13px; margin-left: 12px; }}
  .ts {{ font-size: 11px; color: #718096; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; padding: 24px 32px 0; }}
  .card {{ background: #1a1d27; border: 1px solid #2d3748; border-radius: 10px; padding: 20px; }}
  .card-label {{ font-size: 11px; color: #718096; text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 8px; }}
  .card-value {{ font-size: 28px; font-weight: 700; color: #e2e8f0; }}
  .card-sub {{ font-size: 12px; color: #68d391; margin-top: 4px; }}
  .section {{ padding: 24px 32px; }}
  .section h2 {{ font-size: 14px; font-weight: 600; color: #a0aec0; text-transform: uppercase; letter-spacing: 0.8px; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid #2d3748; }}
  table {{ width: 100%; border-collapse: collapse; background: #1a1d27; border-radius: 10px; overflow: hidden; border: 1px solid #2d3748; }}
  th {{ font-size: 11px; color: #718096; text-transform: uppercase; letter-spacing: 0.6px; padding: 10px 14px; text-align: left; background: #171923; border-bottom: 1px solid #2d3748; }}
  td {{ padding: 10px 14px; font-size: 13px; border-bottom: 1px solid #1e2533; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #1e2533; }}
  .two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; }}
  .highlight {{ color: #68d391; font-weight: 700; }}
  .badge {{ display:inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
  .badge-esc {{ background: #742a2a; color: #fc8181; }}
  .badge-rev {{ background: #744210; color: #f6ad55; }}
  .badge-sup {{ background: #1a365d; color: #63b3ed; }}
  @media (max-width: 768px) {{ .two-col {{ grid-template-columns: 1fr; }} .grid {{ grid-template-columns: 1fr 1fr; }} }}
</style>
</head>
<body>
<div class="topbar">
  <div class="logo">SecOps Hub <span>AI-Powered SOC Dashboard</span></div>
  <div class="ts">Generated: {now}</div>
</div>

<div class="grid">
  <div class="card">
    <div class="card-label">Total Analyst Queries</div>
    <div class="card-value">{roi['total_queries']}</div>
    <div class="card-sub">across all capabilities</div>
  </div>
  <div class="card">
    <div class="card-label">Time Saved</div>
    <div class="card-value">{roi['saved_hours']:.1f}h</div>
    <div class="card-sub">{roi['saved_min']:.0f} minutes vs manual</div>
  </div>
  <div class="card">
    <div class="card-label">Cost Avoided</div>
    <div class="card-value">${roi['dollar_saved']:.0f}</div>
    <div class="card-sub">@ ${ANALYST_HOURLY_RATE_USD}/hr analyst rate</div>
  </div>
  <div class="card">
    <div class="card-label">Cases Generated</div>
    <div class="card-value">{cases_total}</div>
    <div class="card-sub">
      <span class="badge badge-esc">{decision_counts['escalate']} escalated</span>&nbsp;
      <span class="badge badge-rev">{decision_counts['review']} review</span>&nbsp;
      <span class="badge badge-sup">{decision_counts['suppress']} suppressed</span>
    </div>
  </div>
</div>

<div class="section two-col">
  <div>
    <h2>Findings by Severity</h2>
    <table>
      <thead><tr><th>Severity</th><th>Count</th></tr></thead>
      <tbody>{sev_rows}</tbody>
    </table>
  </div>
  <div>
    <h2>ROI Breakdown by Capability</h2>
    <table>
      <thead><tr><th>Capability</th><th>Runs</th><th>Manual</th><th>Automated</th><th>Saved</th></tr></thead>
      <tbody>
        {roi_rows if roi_rows else '<tr><td colspan="5" style="color:#718096;text-align:center">No data yet — run some queries first</td></tr>'}
        <tr style="background:#171923">
          <td colspan="4" style="font-weight:600;color:#a0aec0">Total Saved</td>
          <td style="font-weight:700;color:#68d391">{roi['saved_min']:.1f} min ({roi['saved_hours']:.2f} hrs)</td>
        </tr>
      </tbody>
    </table>
  </div>
</div>

<div class="section">
  <h2>Recent Analyst Activity</h2>
  <table>
    <thead>
      <tr><th>Timestamp</th><th>Capability</th><th>Input</th><th>Severity</th><th>MITRE</th></tr>
    </thead>
    <tbody>
      {recent_rows if recent_rows else '<tr><td colspan="5" style="color:#718096;text-align:center">No findings yet</td></tr>'}
    </tbody>
  </table>
</div>

<div style="padding: 12px 32px 32px; font-size: 11px; color: #4a5568; text-align: center;">
  SecOps Hub &mdash; TRAE Skill &mdash; Tier-1 SOC Automation &mdash; {now}
</div>
</body>
</html>"""
    return html


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=str, default="")
    parser.add_argument("--mock", action="store_true")
    ns = parser.parse_args()

    entries = _load_entries()

    if ns.mock:
        result = {
            "severity": "Info",
            "summary": f"Dashboard would be generated from {len(entries)} journal entries.",
            "mitre": "N/A",
            "action": "Remove --mock to generate the real HTML dashboard.",
        }
        print(json.dumps(result, ensure_ascii=False))
        return 0

    html = generate_html(entries)

    out_path_str = (ns.out or "").strip()
    if not out_path_str:
        out_path_str = str(_skill_dir() / "out" / "dashboard.html")

    out_path = pathlib.Path(out_path_str)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")

    roi = _compute_roi(entries)
    result = {
        "severity": "Info",
        "summary": (
            f"Dashboard generated: {out_path}\n"
            f"Queries: {roi['total_queries']} | Time saved: {roi['saved_hours']:.1f}h | "
            f"Cost avoided: ${roi['dollar_saved']:.0f}"
        ),
        "mitre": "N/A",
        "action": f"Open {out_path} in a browser to view the SOC metrics dashboard.",
    }
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
