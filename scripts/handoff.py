"""Cross-role case handoff generator.

Packages a case bundle into a role-specific document so analysts, IR teams,
and management each receive exactly the information they need — no more.

Usage (standalone):
  python scripts/handoff.py [--role analyst|ir-team|management] [case_path_or_id]

Via dispatch:
  dispatch.py "handoff case-20260530-074813-0001 for management"
  dispatch.py "prepare ir-team briefing for latest case"
"""

import argparse
import datetime as dt
import json
import pathlib
import re
import sys

ROLES = ("analyst", "ir-team", "management")

_SEVERITY_PRIORITY = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def _skill_dir() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1]


def _cases_dir() -> pathlib.Path:
    return _skill_dir() / "out" / "cases"


def _handoffs_dir() -> pathlib.Path:
    return _skill_dir() / "out" / "handoffs"


def _latest_case() -> pathlib.Path | None:
    cases = sorted(_cases_dir().glob("case-*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
    return cases[0] if cases else None


def _find_case(hint: str) -> pathlib.Path | None:
    """Resolve a case ID or partial name to a file path."""
    hint = hint.strip().strip("\"'")
    if not hint:
        return _latest_case()
    p = pathlib.Path(hint)
    if p.exists():
        return p
    # try as bare ID inside cases dir
    for candidate in _cases_dir().glob("case-*.md"):
        if hint in candidate.name:
            return candidate
    return _latest_case()


def _parse_case(path: pathlib.Path) -> dict:
    """Extract structured fields from a case markdown bundle."""
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()

    data: dict = {"raw": text, "path": str(path), "iocs": [], "assets": [], "actions": [], "reasons": []}

    # title
    for ln in lines:
        if ln.startswith("# Case:"):
            data["title"] = ln.removeprefix("# Case:").strip()
            break

    # header fields
    for ln in lines:
        if ln.startswith("**Case ID:**"):
            data["case_id"] = ln.split("**Case ID:**")[-1].strip()
        if ln.startswith("**Generated:**"):
            data["generated"] = ln.split("**Generated:**")[-1].strip()
        if ln.startswith("**Severity:**"):
            m = re.search(r"Severity:\*\*\s*(\w+)", ln)
            if m:
                data["severity"] = m.group(1)
            m = re.search(r"Confidence:\*\*\s*(\d+)%", ln)
            if m:
                data["confidence"] = int(m.group(1))
            m = re.search(r"Verdict:\*\*\s*([\w_]+)", ln)
            if m:
                data["verdict"] = m.group(1)
        if ln.startswith("**Decision:**"):
            data["decision_line"] = ln.split("**Decision:**")[-1].strip()

    # sections
    section = None
    for ln in lines:
        if ln.startswith("## "):
            section = ln.removeprefix("## ").strip().lower()
            continue
        if section == "iocs" and ln.strip().startswith("- ["):
            data["iocs"].append(ln.strip())
        if section == "affected assets (from assets.csv)" and ln.strip().startswith("- **"):
            data["assets"].append(ln.strip())
        if section == "recommended actions" and re.match(r"^\d+\.", ln.strip()):
            data["actions"].append(ln.strip())
        if section == "classification reasoning" and ln.strip().startswith("- "):
            data["reasons"].append(ln.strip().lstrip("- "))

    # alert summary block
    in_summary = False
    summary_lines = []
    for ln in lines:
        if ln.strip() == "## Alert Summary":
            in_summary = True
            continue
        if in_summary and ln.startswith("## "):
            break
        if in_summary and ln.strip():
            summary_lines.append(ln.strip())
    data["alert_summary"] = " ".join(summary_lines[:3])

    data.setdefault("title", path.stem)
    data.setdefault("severity", "Unknown")
    data.setdefault("confidence", 0)
    data.setdefault("verdict", "unknown")
    data.setdefault("decision_line", "")
    data.setdefault("case_id", path.stem)
    data.setdefault("generated", "")

    return data


def _build_analyst(d: dict, ts: str) -> str:
    lines = [
        f"# Analyst Handoff — {d['title']}",
        "",
        f"**Case ID:** {d['case_id']}  |  **Severity:** {d['severity']}  |  **Confidence:** {d['confidence']}%",
        f"**Generated:** {ts}  |  **Verdict:** {d['verdict']}",
        f"**Decision:** {d['decision_line']}",
        "",
        "---",
        "",
        "## Situation",
        "",
        d["alert_summary"] or "_No summary extracted._",
        "",
        "## IOCs for Investigation",
        "",
    ]
    if d["iocs"]:
        lines.extend(d["iocs"])
    else:
        lines.append("No IOCs extracted from this case.")
    lines += [
        "",
        "## Classification Reasoning",
        "",
    ]
    for r in d["reasons"]:
        lines.append(f"- {r}")
    lines += [
        "",
        "## Recommended Actions",
        "",
    ]
    for a in d["actions"]:
        lines.append(a)
    lines += [
        "",
        "## Analyst Checklist",
        "",
        "- [ ] Verify all IOCs in internal threat intel platform",
        "- [ ] Check for related alerts on same host/user in SIEM (last 72h)",
        "- [ ] Run log scan across endpoint telemetry for matching patterns",
        "- [ ] Generate Sigma rule if novel technique detected",
        "- [ ] Document findings in case journal before closing",
        "",
        "## Hunt Queries (Sigma-style)",
        "",
        "```yaml",
        "# Suggested hunt for this case",
        "detection:",
        "  keywords:",
    ]
    # pull keywords from IOCs
    for ioc in d["iocs"][:3]:
        m = re.search(r"\] (.+?)($| \|)", ioc)
        if m:
            lines.append(f"    - '{m.group(1).strip()}'")
    lines += [
        "  condition: keywords",
        "```",
        "",
        "---",
        f"*Analyst handoff generated by secops-hub | {ts}*",
        "",
    ]
    return "\n".join(lines)


def _build_ir_team(d: dict, ts: str) -> str:
    sev = d["severity"]
    lines = [
        f"# IR Team Handoff — {d['title']}",
        "",
        f"**Case ID:** {d['case_id']}  |  **Severity:** {sev}  |  **Confidence:** {d['confidence']}%",
        f"**Decision:** {d['decision_line']}",
        f"**Escalated:** {ts}",
        "",
        "> **IR Team:** This package was auto-escalated by the Tier-1 AI SOC pipeline.",
        "> Verify all findings before taking containment action.",
        "",
        "---",
        "",
        "## Incident Overview",
        "",
        d["alert_summary"] or "_No summary extracted._",
        "",
        "## Affected Assets",
        "",
    ]
    if d["assets"]:
        lines.extend(d["assets"])
    else:
        lines.append("No assets matched from inventory — perform manual host identification.")
    lines += [
        "",
        "## IOC Block List",
        "",
        "_Block the following at firewall / proxy / EDR immediately if verdict is confirmed:_",
        "",
    ]
    for ioc in d["iocs"]:
        lines.append(ioc)
    lines += [
        "",
        "## Containment Checklist",
        "",
        f"### Phase 1 — Immediate ({sev} severity)",
    ]
    if sev == "Critical":
        lines += [
            "- [ ] Isolate affected hosts from the network (VLAN quarantine or agent-based)",
            "- [ ] Revoke active sessions and credentials for affected accounts",
            "- [ ] Block all IOCs at perimeter (firewall, proxy, EDR)",
            "- [ ] Notify CISO and legal team — potential breach declaration may be required",
            "- [ ] Open war-room bridge; assign IR lead",
        ]
    elif sev == "High":
        lines += [
            "- [ ] Block confirmed malicious IOCs at firewall/proxy/EDR",
            "- [ ] Disable affected accounts pending investigation",
            "- [ ] Identify blast radius — search for lateral movement indicators",
            "- [ ] Notify SOC manager and asset owners",
        ]
    else:
        lines += [
            "- [ ] Block IOCs at proxy/EDR as a precaution",
            "- [ ] Monitor affected hosts for 24h before further action",
            "- [ ] Coordinate with asset owner for investigation access",
        ]
    lines += [
        "",
        "### Phase 2 — Evidence Collection",
        "- [ ] Memory dump from affected hosts (volatility-ready)",
        "- [ ] Collect event logs (Security, System, PowerShell, Sysmon) for ±2h window",
        "- [ ] Capture network flow records from affected segments",
        "- [ ] Preserve disk image if data exfiltration is suspected",
        "- [ ] Document chain of custody for all collected artifacts",
        "",
        "### Phase 3 — Eradication",
        "- [ ] Remove malicious files/processes identified in investigation",
        "- [ ] Patch or mitigate the exploited vulnerability",
        "- [ ] Reset all credentials exposed during the incident",
        "- [ ] Rebuild affected systems from known-good baseline if persistence found",
        "",
        "## Classification Reasoning",
        "",
    ]
    for r in d["reasons"]:
        lines.append(f"- {r}")
    lines += [
        "",
        "---",
        f"*IR Team handoff generated by secops-hub | {ts}*",
        "",
    ]
    return "\n".join(lines)


def _build_management(d: dict, ts: str) -> str:
    sev = d["severity"]
    conf = d["confidence"]
    asset_count = len(d["assets"])
    ioc_count = len(d["iocs"])

    risk_label = {
        "Critical": "CRITICAL — Immediate executive attention required",
        "High": "HIGH — Escalated to IR team; monitoring closely",
        "Medium": "MEDIUM — Under investigation by security team",
        "Low": "LOW — Logged; no immediate action required",
        "Info": "INFORMATIONAL — No action required",
    }.get(sev, sev)

    lines = [
        f"# Executive Briefing — Security Incident",
        "",
        f"**Reference:** {d['case_id']}",
        f"**Risk Level:** {risk_label}",
        f"**AI Confidence:** {conf}% | **Decision:** {d['decision_line']}",
        f"**Prepared:** {ts}",
        "",
        "---",
        "",
        "## What Happened",
        "",
        d["alert_summary"] or "_Alert details are being analyzed by the security team._",
        "",
        "## Business Impact at a Glance",
        "",
        f"| Metric | Value |",
        f"|---|---|",
        f"| Severity | {sev} |",
        f"| AI Confidence Score | {conf}% |",
        f"| Assets Potentially Affected | {asset_count if asset_count else 'Under investigation'} |",
        f"| Indicators of Compromise | {ioc_count} identified |",
        f"| Automated Decision | {d['decision_line'].split('—')[0].strip() if '—' in d['decision_line'] else d['decision_line']} |",
        "",
        "## What the Security Team is Doing",
        "",
    ]
    if sev == "Critical":
        lines += [
            "1. **Containment** — Affected systems are being isolated to prevent spread",
            "2. **Investigation** — IR team is collecting evidence and tracing the attack path",
            "3. **Notification** — Legal and compliance teams are being briefed",
            "4. **Recovery** — Remediation plan will be presented within 4 hours",
        ]
    elif sev == "High":
        lines += [
            "1. **Triage** — Tier-2 analysts are validating and enriching the alert",
            "2. **Containment** — Malicious indicators are being blocked at the perimeter",
            "3. **Monitoring** — Affected systems are under heightened observation",
            "4. **Update** — Security team will provide a status update within 2 hours",
        ]
    else:
        lines += [
            "1. **Review** — Security team is assessing the alert during normal operations",
            "2. **Monitoring** — No immediate containment action required at this time",
            "3. **Update** — Findings will be included in the next security operations report",
        ]
    lines += [
        "",
        "## Decision Required",
        "",
    ]
    if sev in ("Critical", "High") and "escalate" in d["decision_line"].lower():
        lines += [
            "- [ ] **Approve incident response engagement** — authorize IR team to proceed with full containment",
            "- [ ] **Notify cyber insurance carrier** if policy requires it",
            "- [ ] **Assess breach notification obligations** with legal counsel",
            "- [ ] **Approve emergency change** if system shutdown is required",
        ]
    else:
        lines += [
            "- [ ] **Acknowledge** — confirm security team has management awareness",
            "- [ ] **No immediate action required** from leadership at this time",
        ]
    lines += [
        "",
        "## Key Contact",
        "",
        "Security Operations Center (SOC) — escalate via Telegram alert channel or on-call pager",
        "",
        "---",
        f"*Executive briefing auto-generated by SecOps Hub AI SOC | {ts}*",
        "*This summary was produced by the Tier-1 automation pipeline. All findings should be*",
        "*confirmed by the security team before external communication.*",
        "",
    ]
    return "\n".join(lines)


_BUILDERS = {
    "analyst":    _build_analyst,
    "ir-team":    _build_ir_team,
    "management": _build_management,
}


def generate(case_hint: str, role: str) -> dict:
    role = role.lower().strip()
    if role not in ROLES:
        role = "analyst"

    case_path = _find_case(case_hint)
    if case_path is None or not case_path.exists():
        return {
            "severity": "Info",
            "summary": f"No case found matching '{case_hint}'. Run the pipeline first to generate cases.",
            "mitre": "N/A",
            "action": "Run: dispatch.py 'generate demo alerts' then dispatch.py 'process all pending alerts'",
        }

    d = _parse_case(case_path)
    ts = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    md = _BUILDERS[role](d, ts)

    out_dir = _handoffs_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    out_name = f"handoff-{role}-{d['case_id']}.md"
    out_path = out_dir / out_name
    out_path.write_text(md, encoding="utf-8")

    return {
        "severity": d.get("severity", "Info"),
        "summary": f"[{role.upper()} HANDOFF] {d['title']}\n\nPackage written: {out_path}\n\n"
                   + md[:800] + ("..." if len(md) > 800 else ""),
        "mitre": "N/A",
        "action": f"Share {out_path} with the {role} team. "
                  f"Generate all three roles: analyst, ir-team, management.",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--role", choices=ROLES, default="analyst")
    parser.add_argument("--mock", action="store_true")
    parser.add_argument("case", nargs="?", default="")
    ns = parser.parse_args()

    if ns.mock:
        result = {
            "severity": "High",
            "summary": "[MOCK] Handoff document would be generated here for role: " + ns.role,
            "mitre": "N/A",
            "action": "Remove --mock and provide a case ID to generate a real handoff.",
        }
    else:
        result = generate(ns.case, ns.role)

    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
