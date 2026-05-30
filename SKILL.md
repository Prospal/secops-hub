---
name: secops-hub
description: "SecOps analyst hub: triage IOCs, look up CVEs, generate Sigma detection rules, automate Tier-1 SOC alert pipeline, and produce cross-role handoff packages for analysts, IR teams, and management. Invoke when the user pastes a security indicator, alert, or CVE ID, asks for a detection rule, or wants to share a case with their team."
---

# SecOps Hub

Turn TRAE into a security team's analyst hub. An analyst asks a security question
in plain language and you (the model) route it to the right capability, run the
matching script, and present the result. **You decide which capability applies and
run the script — the scripts do not auto-run.**

## Quick demo entrypoint (recommended)

Run one command for any analyst input:

```
python .trae/skills/secops-hub/scripts/dispatch.py "CVE-2024-3094"
python .trae/skills/secops-hub/scripts/dispatch.py "mimikatz dumping lsass"
python .trae/skills/secops-hub/scripts/dispatch.py "write a detection rule for powershell downloading a file"
python .trae/skills/secops-hub/scripts/dispatch.py "generate demo alerts"
python .trae/skills/secops-hub/scripts/dispatch.py "process all pending alerts"
python .trae/skills/secops-hub/scripts/dispatch.py "handoff latest case for management"
python .trae/skills/secops-hub/scripts/dispatch.py "generate dashboard"
```

`dispatch.py` writes every run to a local journal at `.trae/skills/secops-hub/out/findings.jsonl`.

## Cross-Role Collaboration (TRAE as Unified Entry Point)

SecOps Hub is designed for multi-role teams. The same TRAE conversation can serve
an analyst, escalate to the IR team, and brief management — without switching tools.

### Role-Based Handoff Workflow

```
Analyst (TRAE)
    │
    ├─▶ IOC Triage / CVE Lookup / Detection Rules     ← analyst daily work
    │
    ├─▶ AI SOC Pipeline (alert → enrich → classify → escalate)
    │         │
    │         ├─▶ out/cases/case-*.md                  ← auto-generated evidence bundle
    │         │
    │         ├─▶ handoff --role analyst               ← analyst view: IOCs + hunt queries
    │         ├─▶ handoff --role ir-team               ← IR view: containment + forensics
    │         └─▶ handoff --role management            ← exec view: impact + decisions
    │
    └─▶ generate dashboard                             ← real-time ROI + metrics for leadership
```

### Example Multi-Role Session

```
# Analyst generates and processes alerts
dispatch.py "generate demo alerts"
dispatch.py "process all pending alerts"

# Analyst prepares handoffs for each audience (all from TRAE)
dispatch.py "handoff latest case for ir-team"
dispatch.py "handoff latest case for management"
dispatch.py "handoff latest case for analyst"

# Leadership views metrics
dispatch.py "generate dashboard"
```

Handoff documents are saved to `out/handoffs/handoff-<role>-<case-id>.md`.

## ROI Metrics

SecOps Hub quantifies the time and cost saved by automating analyst work.

| Capability | Manual Time | Automated | Time Saved/Run |
|---|---|---|---|
| IOC Triage | 20 min | 30 sec | **~19.5 min** |
| CVE Lookup | 10 min | 15 sec | **~9.75 min** |
| Detection Rule | 90 min | 45 sec | **~89.25 min** |
| Log Scan | 30 min | 20 sec | **~29.67 min** |
| Alert Pipeline | 20 min/alert | 45 sec | **~19.25 min** |
| Asset Scan | 15 min | 20 sec | **~14.67 min** |

> At $65/hr analyst rate: **10 alert triage runs ≈ $210 saved**. A detection rule alone saves **~1.5 hrs**.

Generate an always-current ROI report:

```
python .trae/skills/secops-hub/scripts/report.py
python .trae/skills/secops-hub/scripts/dispatch.py "generate dashboard"
```

## All Capabilities

| Analyst input looks like… | Capability | Script |
|---|---|---|
| An IOC — IP, domain, file hash, or URL | **Triage** | `scripts/triage.py` |
| A CVE ID (e.g. `CVE-2024-3094`) | **CVE lookup** | `scripts/cve_lookup.py` |
| A plain-language attack description, or "write a detection rule for…" | **Detection rule** | `scripts/detection_rule.py` |
| "generate logs/events for …" | **Synthetic logs** | `scripts/synthetic_logs.py` |
| "generate demo logs" | **Demo logs to file** | `scripts/demo_logs.py` |
| "scan logs <path>" | **Log scan** | `scripts/log_scan.py` |
| "generate demo alerts" | **Alert simulator** | `scripts/alert_simulator.py` |
| "process all pending alerts" | **Pipeline** | `scripts/pipeline.py` |
| "handoff [case] for [analyst\|ir-team\|management]" | **Cross-role handoff** | `scripts/handoff.py` |
| "generate dashboard" / "show metrics" / "roi" | **SOC Dashboard** | `scripts/dashboard.py` |

## AI SOC Pipeline (Tier-1 Automation)

The pipeline automates what a Tier-1 SOC analyst does: ingest alerts → enrich IOCs →
classify false positives → decide escalation → produce an evidence bundle.

### Pipeline flow

```
in/alerts/alert-*.json  →  enrich.py  →  classify.py  →  escalate.py  →  bundle.py
                                                              │
                                                              ▼
                                                  out/cases/case-*.md
                                                              │
                                                  handoff.py (all 3 roles)
```

### How to use

```
python .trae/skills/secops-hub/scripts/dispatch.py --json "generate demo alerts"
python .trae/skills/secops-hub/scripts/dispatch.py --json "process all pending alerts"
python .trae/skills/secops-hub/scripts/pipeline.py --watch
```

`pipeline.py` watches `in/alerts/` for new `.json` files, runs the full enrichment →
classification → escalation → bundle chain for each, and moves processed files to
`in/processed/`.  Escalated findings are pushed to Telegram (if configured).

| Step | Script | What it does |
|---|---|---|
| **Alert Ingestion** | `in/alerts/` drop zone | Drop JSON alert files; pipeline auto-picks them up |
| **Enrich** | `scripts/enrich.py` | GreyNoise + passive DNS mock context for every IOC |
| **Classify** | `scripts/classify.py` | False-positive filter — confidence score 0-100 with reasoning |
| **Escalate** | `scripts/escalate.py` | Needs-human gate: escalate / review / suppress |
| **Bundle** | `scripts/bundle.py` | Evidence bundle → `out/cases/case-<id>.md` (IOCs, timeline, affected assets, MITRE, actions) |
| **Handoff** | `scripts/handoff.py` | Role-specific package → `out/handoffs/handoff-<role>-<case>.md` |

## How to run a capability

All scripts take the analyst's input as a single string argument and print one JSON
object to stdout. Run from the skill directory:

```
python .trae/skills/secops-hub/scripts/triage.py "185.220.101.5"
python .trae/skills/secops-hub/scripts/cve_lookup.py "CVE-2024-3094"
python .trae/skills/secops-hub/scripts/detection_rule.py "powershell downloading a file from a suspicious domain"
python .trae/skills/secops-hub/scripts/synthetic_logs.py "generate logs for mimikatz dumping lsass"
python .trae/skills/secops-hub/scripts/demo_logs.py
python .trae/skills/secops-hub/scripts/log_scan.py ".trae/skills/secops-hub/out/telemetry/demo_events.jsonl"
python .trae/skills/secops-hub/scripts/handoff.py --role management
python .trae/skills/secops-hub/scripts/dashboard.py
```

(Paths are relative to the workspace root. If the working directory is the skill
folder, `python scripts/<name>.py "..."` also works.)

## The output contract

Every script returns exactly these four keys. Present them to the analyst as a tidy
finding — lead with severity, then the summary, then the MITRE mapping and the
recommended action:

```json
{
  "severity": "Critical | High | Medium | Low | Info",
  "summary": "Short human-readable finding (for detection rules, this holds the Sigma YAML).",
  "mitre": "Txxxx - Technique Name (or 'N/A')",
  "action": "Recommended next step for the analyst."
}
```

When the script returns a Sigma rule in `summary`, render it as a YAML code block.

When presenting results in chat, always use this clean layout:

- severity: <value>
- summary: <value> (use a code block if this is Sigma YAML or JSONL events)
- mitre: <value>
- action: <value>

## Enriching the result (optional, recommended)

The scripts are the reliable baseline. After running one, you may enrich it: for a
detection rule, refine the Sigma logic to better fit the analyst's description; for a
CVE with `mitre: "N/A"`, suggest a likely ATT&CK technique and say it's inferred.
Never replace the script's factual fields (CVSS severity, NVD description) with
guesses — enrich around them.

## Offline / production mode

Many production networks block outbound internet. For that environment:

- Set `SECOPS_HUB_OFFLINE=1` to force offline mode (CVE lookup uses mock/fallback; triage uses mock/fallback unless you provide internal enrichment keys).
- For a production-grade CVE pipeline, mirror vulnerability data into your network segment and query that mirror instead of calling public APIs directly.

## Environment (.env)

`dispatch.py` auto-loads `.trae/skills/secops-hub/.env` (if present) and exports variables for child scripts.
Copy `.env.example` to `.env`, then fill values:

- `NVD_API_KEY` (optional): reduces NVD throttling for CVE lookup
- `VIRUSTOTAL_API_KEY` (optional): enables VirusTotal enrichment in `triage.py`
- `ABUSEIPDB_API_KEY` (optional): enables AbuseIPDB enrichment in `triage.py`
- `TELEGRAM_BOT_TOKEN` (optional): Telegram bot token for push notifications on escalations
- `TELEGRAM_CHAT_ID` (optional): Telegram chat ID for push notifications
- `SECOPS_HUB_WEBHOOK_URL` (optional): POST each run to a webhook endpoint
- `SECOPS_HUB_OFFLINE` (optional): force offline mode

## Reliability / fallback

Each script falls back to realistic canned data if its API fails, times out, or is
rate-limited (NVD throttles unauthenticated requests). A failed lookup therefore
still returns a valid contract object — present it normally. If you ever cannot run a
script at all, say so plainly rather than inventing a finding.

## Self-test

To confirm the skill is wired up, run each script with `--mock` and check that each
prints a valid JSON object with the four keys:

```
python .trae/skills/secops-hub/scripts/cve_lookup.py --mock
python .trae/skills/secops-hub/scripts/detection_rule.py --mock
python .trae/skills/secops-hub/scripts/triage.py --mock
python .trae/skills/secops-hub/scripts/synthetic_logs.py --mock
python .trae/skills/secops-hub/scripts/handoff.py --mock
python .trae/skills/secops-hub/scripts/dashboard.py --mock
python .trae/skills/secops-hub/scripts/dispatch.py --mock "CVE-2024-3094"
```

## Webhook push (optional)

If you want a seamless demo "SIEM ingest", set `SECOPS_HUB_WEBHOOK_URL` to an HTTPS endpoint.
`dispatch.py` will POST each journal entry as JSON to that URL.

## Report export

Generate a shareable markdown report (includes ROI breakdown):

```
python .trae/skills/secops-hub/scripts/report.py --out .trae/skills/secops-hub/out/report.md
```

Generate an HTML dashboard with live metrics:

```
python .trae/skills/secops-hub/scripts/dashboard.py --out .trae/skills/secops-hub/out/dashboard.html
```
