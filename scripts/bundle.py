import datetime as dt
import json
import pathlib
import sys


def _skill_dir() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1]


def _cases_dir() -> pathlib.Path:
    return _skill_dir() / "out" / "cases"


def _assets_path() -> pathlib.Path:
    return _skill_dir() / "assets.csv"


def _load_assets() -> list[dict]:
    p = _assets_path()
    if not p.exists():
        return []
    lines = p.read_text(encoding="utf-8").strip().splitlines()
    if len(lines) < 2:
        return []
    headers = [h.strip().lower() for h in lines[0].split(",")]
    rows = []
    for line in lines[1:]:
        vals = [v.strip() for v in line.split(",")]
        if len(vals) == len(headers):
            rows.append(dict(zip(headers, vals)))
    return rows


def _match_assets(keywords: list[str]) -> list[dict]:
    assets = _load_assets()
    if not keywords or not assets:
        return []
    kw_lower = set(k.lower() for k in keywords)
    matched = []
    for a in assets:
        product = (a.get("product", "") or "").lower()
        notes = (a.get("notes", "") or "").lower()
        if any(k in product or k in notes for k in kw_lower):
            matched.append(a)
    return matched[:5]


def build(alert, enriched, classification, escalation):
    alert_id = alert.get("id", "unknown")
    severity = alert.get("severity", "Info")
    alert_type = alert.get("type", "unknown")
    source = alert.get("source", "unknown")
    title = alert.get("title", "Untitled Alert")
    raw_text = alert.get("raw_text", "")
    confidence = classification.get("confidence", 0)
    verdict = classification.get("verdict", "unknown")
    decision = escalation.get("decision", "review")
    reason = escalation.get("reason", "")
    keywords = alert.get("keywords", [])
    enriched_iocs = enriched.get("enriched_iocs", {})
    threat_context = enriched.get("threat_context", "")

    ioc_list = []
    for kind in ("ip", "domain", "url", "sha256", "md5", "sha1"):
        for item in enriched_iocs.get(kind, []):
            extra = ""
            val = item.get("value", "")
            if kind == "ip" and item.get("greynoise"):
                gn = item["greynoise"]
                extra = f" | GreyNoise: {gn.get('classification', 'unknown')} ({', '.join(gn.get('tags', []))})"
            elif kind == "domain" and item.get("passive_dns"):
                pdns = item["passive_dns"]
                res = pdns.get("resolutions", [])
                if res:
                    extra = f" | resolves to {res[-1]['ip']} | registrar: {pdns.get('registrar','?')} | created: {pdns.get('created','?')}"
            ioc_list.append(f"  - [{kind.upper()}] {val}{extra}")

    affected = _match_assets(keywords)

    ts = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    case_id = f"case-{alert_id.replace('alert-', '')}"

    lines = [
        f"# Case: {title}",
        "",
        f"**Case ID:** {case_id}",
        f"**Generated:** {ts}",
        f"**Severity:** {severity} | **Confidence:** {confidence}% | **Verdict:** {verdict}",
        f"**Decision:** {decision.upper()} — {reason}",
        "",
        "---",
        "",
        "## Alert Summary",
        "",
        alert.get("raw_text", ""),
        "",
        f"- Type: {alert_type}",
        f"- Source: {source}",
        f"- Keywords: {', '.join(keywords) if keywords else 'none'}",
        "",
        "## IOCs",
        "",
    ]
    if ioc_list:
        lines.extend(ioc_list)
    else:
        lines.append("  No IOCs extracted.")
    lines += [
        "",
        "## Threat Context",
        "",
        threat_context or "No threat context available.",
        "",
    ]

    if affected:
        lines += [
            "## Affected Assets (from assets.csv)",
            "",
        ]
        for a in affected:
            lines.append(f"- **{a.get('name', '?')}** ({a.get('asset_type', '?')}) | product: {a.get('product', '?')} v{a.get('version', '?')} | env: {a.get('environment', '?')} | exposure: {a.get('exposure', '?')} | owner: {a.get('owner', '?')}")
        lines.append("")

    lines += [
        "## Classification Reasoning",
        "",
    ]
    for r in classification.get("reasons", []):
        lines.append(f"- {r}")
    lines += [
        "",
        "## Classification Details",
        "",
        f"- Confidence: {confidence}%",
        f"- Verdict: {verdict}",
        f"- Decision: {decision}",
        f"- Needs Human: {'YES' if escalation.get('needs_human') else 'NO'}",
        "",
        "## Recommended Actions",
        "",
    ]
    if severity in ("Critical",) and decision == "escalate":
        lines += [
            "1. Treat as active incident — begin containment immediately",
            "2. Isolate affected hosts from the network",
            "3. Collect forensic artifacts (memory dump, disk image, network captures)",
            "4. Hunt for lateral movement and persistence mechanisms",
            "5. Notify incident response team and leadership",
        ]
    elif severity == "High" and decision == "escalate":
        lines += [
            "1. Escalate to Tier-2 analyst for deeper investigation",
            "2. Block identified IOCs at firewall/proxy/EDR",
            "3. Search for additional instances of the same pattern across the environment",
            "4. Review asset inventory for potentially affected systems",
        ]
    elif decision == "review":
        lines += [
            "1. Queue for Tier-2 review within the shift",
            "2. Enrich IOCs with additional sources if available",
            "3. Correlate with other recent alerts for the same host/user",
        ]
    else:
        lines += [
            "1. Record in journal for trend analysis",
            "2. No immediate action required — classified as likely false positive",
            "3. Monitor for recurrence; escalate if pattern repeats",
        ]

    lines += [
        "",
        "---",
        f"*Generated by secops-hub | {ts}*",
        "",
    ]

    return "\n".join(lines)


def main():
    if len(sys.argv) > 1:
        data = sys.argv[1]
        if data.strip().startswith("{"):
            payload = json.loads(data)
        else:
            with open(data, encoding="utf-8") as f:
                payload = json.load(f)
    else:
        payload = json.loads(sys.stdin.read())

    alert = payload.get("alert", {})
    enriched = payload.get("enriched", {})
    classification = payload.get("classification", {})
    escalation = payload.get("escalation", {})

    md = build(alert, enriched, classification, escalation)

    out_dir = _cases_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    alert_id = alert.get("id", f"case-{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%d-%H%M%S')}")
    case_id = f"case-{alert_id.replace('alert-', '')}"
    case_path = out_dir / f"{case_id}.md"
    case_path.write_text(md, encoding="utf-8")

    result = {
        "severity": alert.get("severity", "Info"),
        "summary": f"Case bundle written: {case_path}",
        "mitre": "N/A",
        "action": escalation.get("reason", "Review the case bundle for next steps.")
    }
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
