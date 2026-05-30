import argparse
import datetime as dt
import json
import pathlib
import sys

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
ANALYST_HOURLY_RATE_USD = 65


def _skill_dir() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1]


def _journal_path() -> pathlib.Path:
    return _skill_dir() / "out" / "findings.jsonl"


def _load_entries(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        return []
    items: list[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                items.append(json.loads(line))
            except Exception:
                continue
    return items


def _md_escape(s: str) -> str:
    return (s or "").replace("\r", "").strip()


def _compute_roi(entries: list[dict]) -> dict:
    total_manual = 0.0
    total_auto_sec = 0.0
    by_cap: dict[str, int] = {}
    for e in entries:
        cap = e.get("capability", "triage")
        by_cap[cap] = by_cap.get(cap, 0) + 1
        b = ROI_BASELINES.get(cap, {"manual_min": 10, "auto_sec": 30})
        total_manual += b["manual_min"]
        total_auto_sec += b["auto_sec"]
    saved_min = max(0, total_manual - total_auto_sec / 60)
    saved_hrs = saved_min / 60
    return {
        "total_manual_min": total_manual,
        "saved_min": saved_min,
        "saved_hrs": saved_hrs,
        "dollar_saved": saved_hrs * ANALYST_HOURLY_RATE_USD,
        "by_cap": by_cap,
    }


def _render(entries: list[dict]) -> str:
    now = (
        dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    lines: list[str] = []
    lines.append(f"# SecOps Hub Report")
    lines.append("")
    lines.append(f"Generated: {now}")
    lines.append(f"Entries: {len(entries)}")
    lines.append("")

    # ROI summary
    roi = _compute_roi(entries)
    lines.append("## ROI Summary")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|---|---|")
    lines.append(f"| Total queries automated | {len(entries)} |")
    lines.append(f"| Estimated manual time | {roi['total_manual_min']:.0f} min |")
    lines.append(f"| Time saved | **{roi['saved_min']:.0f} min ({roi['saved_hrs']:.1f} hrs)** |")
    lines.append(f"| Cost avoided (@ ${ANALYST_HOURLY_RATE_USD}/hr) | **${roi['dollar_saved']:.0f}** |")
    lines.append("")
    lines.append("### Breakdown by Capability")
    lines.append("")
    lines.append("| Capability | Runs | Manual/run | Saved |")
    lines.append("|---|---|---|---|")
    for cap, count in sorted(roi["by_cap"].items(), key=lambda x: -x[1]):
        b = ROI_BASELINES.get(cap, {"manual_min": 10, "auto_sec": 30, "label": cap})
        saved = (b["manual_min"] * count) - (b["auto_sec"] * count / 60)
        lines.append(f"| {b['label']} | {count} | {b['manual_min']} min | {saved:.1f} min |")
    lines.append("")

    for i, e in enumerate(reversed(entries[-50:]), start=1):
        res = (e.get("result") or {}) if isinstance(e, dict) else {}
        lines.append(f"## Finding {i}")
        lines.append("")
        lines.append(f"- Time: {_md_escape(str(e.get('ts', '')))}")
        lines.append(f"- Capability: {_md_escape(str(e.get('capability', '')))}")
        lines.append(f"- Severity: {_md_escape(str(res.get('severity', '')))}")
        lines.append(f"- MITRE: {_md_escape(str(res.get('mitre', '')))}")
        lines.append("")
        lines.append("**Input**")
        lines.append("")
        lines.append("```text")
        lines.append(_md_escape(str(e.get("input", ""))))
        lines.append("```")
        lines.append("")
        lines.append("**Summary**")
        lines.append("")
        summary = str(res.get("summary", ""))
        if "title:" in summary and "detection:" in summary:
            lines.append("```yaml")
            lines.append(_md_escape(summary))
            lines.append("```")
        else:
            lines.append("```text")
            lines.append(_md_escape(summary))
            lines.append("```")
        lines.append("")
        lines.append("**Action**")
        lines.append("")
        lines.append(_md_escape(str(res.get("action", ""))))
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--out", type=str, default="")
    ns = parser.parse_args()

    entries = _load_entries(_journal_path())
    md = _render(entries)

    out_path = (ns.out or "").strip()
    if out_path:
        p = pathlib.Path(out_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(md, encoding="utf-8")

    sys.stdout.write(md)
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
