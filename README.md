# SecOps Hub

A security operations analyst hub built as a TRAE skill. Gives analysts AI-assisted triage for IOCs, CVE lookups, Sigma rule generation, alert processing, and automated Tier-1 SOC workflows — all from plain-language input.

---

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Capabilities](#capabilities)
- [AI SOC Pipeline](#ai-soc-pipeline)
- [Output Contract](#output-contract)
- [Configuration](#configuration)
- [Directory Structure](#directory-structure)
- [Script Reference](#script-reference)
- [Self-Test](#self-test)
- [Offline Mode](#offline-mode)
- [Report Export](#report-export)

---

## Overview

SecOps Hub turns TRAE into a Tier-1 SOC analyst hub. An analyst describes what they need in plain language — paste an IP, drop a CVE ID, describe an attack pattern — and the skill routes it to the right capability, runs the matching script, and returns a structured finding.

**What it automates:**

- IOC enrichment (IP reputation, passive DNS, file hash context)
- CVE lookup with CVSS severity, EPSS exploitation probability, and CISA KEV status
- Sigma detection rule generation from plain-language attack descriptions
- Synthetic log/event generation for detection testing
- Automated alert triage pipeline (enrich → classify → escalate → case bundle)
- Asset impact assessment against your inventory
- Windows Event Log conversion to queryable JSONL

All scripts fall back to realistic mock data when APIs are unavailable, so the skill works in air-gapped or rate-limited environments.

---

## Quick Start

Run any analyst input through the smart dispatcher:

```bash
# Triage an indicator of compromise
python scripts/dispatch.py "185.220.101.5"

# Look up a CVE
python scripts/dispatch.py "CVE-2024-3094"

# Generate a Sigma detection rule
python scripts/dispatch.py "write a detection rule for powershell downloading from a suspicious domain"

# Generate demo alerts and run the full SOC pipeline
python scripts/dispatch.py "generate demo alerts"
python scripts/dispatch.py "process all pending alerts"
```

The dispatcher writes every run to `out/findings.jsonl` as an audit journal.

---

## Capabilities

| Analyst Input | Capability | Script |
|---|---|---|
| IP address, domain, URL, or file hash | Triage | `scripts/triage.py` |
| CVE ID (e.g. `CVE-2024-3094`) | CVE Lookup | `scripts/cve_lookup.py` |
| Plain-language attack description | Detection Rule | `scripts/detection_rule.py` |
| "generate logs for [attack scenario]" | Synthetic Logs | `scripts/synthetic_logs.py` |
| "generate demo logs" | Demo Logs | `scripts/demo_logs.py` |
| "scan logs [path]" | Log Scan | `scripts/log_scan.py` |
| "generate demo alerts" | Alert Simulator | `scripts/alert_simulator.py` |
| "process all pending alerts" | Pipeline | `scripts/pipeline.py` |
| EVTX file path | EVTX Converter | `scripts/evtx_to_jsonl.py` |

### IOC Triage

Extracts and enriches indicators of compromise with GreyNoise classification and passive DNS context.

```bash
python scripts/triage.py "185.220.101.5"
python scripts/triage.py "malware.example.com"
python scripts/triage.py "d41d8cd98f00b204e9800998ecf8427e"
```

Optional: set `VIRUSTOTAL_API_KEY` or `ABUSEIPDB_API_KEY` for live enrichment.

### CVE Lookup

Queries NVD for CVE details, FIRST.org for EPSS exploitation probability, and CISA KEV for known-exploited status.

```bash
python scripts/cve_lookup.py "CVE-2021-44228"
python scripts/cve_lookup.py "CVE-2024-3094"
```

Optional: set `NVD_API_KEY` to avoid rate limiting.

### Detection Rule Generation

Generates Sigma rules from plain-language attack descriptions using keyword extraction and rule templates.

```bash
python scripts/detection_rule.py "mimikatz dumping lsass"
python scripts/detection_rule.py "lateral movement via psexec"
python scripts/detection_rule.py "suspicious powershell encoded command execution"
```

Output is a valid Sigma YAML rule ready for use in a SIEM.

### Synthetic Log Generation

Produces Windows event JSONL files that match a given attack scenario, useful for testing detection rules.

```bash
python scripts/synthetic_logs.py "generate logs for mimikatz dumping lsass"
python scripts/synthetic_logs.py "lateral movement via psexec"
```

### Log Scanning

Hunts a JSONL event log against detection rules to surface matching events.

```bash
python scripts/log_scan.py "out/telemetry/demo_events.jsonl"
```

### EVTX Conversion

Converts Windows Event Viewer `.evtx` files to JSONL format for scanning.

```bash
python scripts/evtx_to_jsonl.py "C:\Windows\System32\winevt\Logs\Security.evtx"
```

---

## AI SOC Pipeline

The pipeline automates the full Tier-1 analyst workflow: ingest alert JSON files, enrich IOCs, score false-positive likelihood, gate escalation decisions, and produce an evidence bundle.

### Flow

```
in/alerts/alert-*.json
        │
        ▼
   enrich.py        ← GreyNoise + passive DNS context for every IOC
        │
        ▼
  classify.py       ← Confidence score 0–100 with reasoning
        │
        ▼
  escalate.py       ← ESCALATE (≥80% + high severity) | REVIEW (50–79%) | SUPPRESS (<50%)
        │
        ▼
   bundle.py        ← Markdown case file with IOCs, assets, MITRE, actions
        │
        ▼
out/cases/case-*.md
        │
        ▼ (if ESCALATE + Telegram configured)
Telegram notification
```

### Running the Pipeline

```bash
# Step 1: Generate sample alerts
python scripts/dispatch.py "generate demo alerts"

# Step 2: Process all pending alerts
python scripts/dispatch.py "process all pending alerts"

# Or: watch the drop zone for new alerts continuously
python scripts/pipeline.py --watch
```

Processed alerts are moved from `in/alerts/` to `in/processed/` automatically.

### Alert Format

Drop JSON files into `in/alerts/` with this structure:

```json
{
  "id": "alert-001",
  "timestamp": "2026-05-30T10:00:00Z",
  "type": "malware",
  "title": "Suspicious process injection detected",
  "severity": "High",
  "source": "EDR",
  "raw_text": "Process lsass.exe accessed by mimikatz.exe",
  "iocs": {
    "ip": ["185.220.101.5"],
    "domain": ["evil.example.com"],
    "sha256": ["abc123..."],
    "md5": [],
    "sha1": [],
    "url": []
  },
  "keywords": ["mimikatz", "lsass", "credential dumping"]
}
```

### Case Bundle Output

Each processed alert produces a markdown case file in `out/cases/` containing:

- Case ID, severity, confidence score, verdict, and decision
- Alert summary and raw text
- Enriched IOCs with GreyNoise classification and passive DNS
- Affected assets matched from `assets.csv`
- Classification reasoning
- MITRE ATT&CK technique mapping
- Recommended actions tiered by severity

---

## Output Contract

Every script returns exactly four keys:

```json
{
  "severity": "Critical | High | Medium | Low | Info",
  "summary": "Human-readable finding. For detection rules, this is the Sigma YAML.",
  "mitre": "Txxxx - Technique Name  (or 'N/A')",
  "action": "Recommended next step for the analyst."
}
```

This consistent schema means any script's output can be presented, journaled, or forwarded to a webhook identically.

---

## Configuration

Copy `.env.example` to `.env` in the skill directory and fill in any keys you have:

```bash
cp .env.example .env
```

| Variable | Required | Purpose |
|---|---|---|
| `NVD_API_KEY` | No | Reduces NVD rate-limiting for CVE lookups |
| `VIRUSTOTAL_API_KEY` | No | Enables VirusTotal enrichment in triage |
| `ABUSEIPDB_API_KEY` | No | Enables AbuseIPDB enrichment in triage |
| `TELEGRAM_BOT_TOKEN` | No | Telegram bot token for escalation push notifications |
| `TELEGRAM_CHAT_ID` | No | Telegram chat ID for push notifications |
| `SECOPS_HUB_WEBHOOK_URL` | No | POST each journal entry as JSON to this endpoint |
| `SECOPS_HUB_OFFLINE` | No | Set to `1` to force offline/mock mode |

`dispatch.py` auto-loads `.env` and exports variables to all child scripts.

### Asset Inventory

Edit `assets.csv` to list your environment's assets. The pipeline matches alert keywords against this file during bundling.

```
hostname,ip,os,owner,criticality,services
web-prod-01,10.10.1.10,Ubuntu 22.04,Platform,Critical,nginx:443
db-prod-01,10.10.1.20,Ubuntu 22.04,Data,Critical,postgresql:5432
```

---

## Directory Structure

```
secops-hub/
├── README.md               ← This file
├── SKILL.md                ← TRAE skill definition (model instructions)
├── .env.example            ← Environment template
├── .env                    ← Your secrets (git-ignored)
├── assets.csv              ← Asset inventory for impact assessment
├── example_alert.json      ← Sample alert for reference
│
├── scripts/
│   ├── dispatch.py         ← Smart router — main entrypoint
│   ├── pipeline.py         ← Automated alert processing pipeline
│   ├── triage.py           ← IOC enrichment
│   ├── cve_lookup.py       ← CVE + EPSS + KEV lookup
│   ├── detection_rule.py   ← Sigma rule generation
│   ├── enrich.py           ← IOC enrichment (used by pipeline)
│   ├── classify.py         ← Confidence scoring
│   ├── escalate.py         ← Escalation decision gate
│   ├── bundle.py           ← Case evidence bundling
│   ├── alert_simulator.py  ← Mock alert generator
│   ├── synthetic_logs.py   ← Attack scenario log generation
│   ├── demo_logs.py        ← Demo log ingestion
│   ├── log_scan.py         ← Log hunting against detection rules
│   ├── scan_assets.py      ← Vulnerable asset matching
│   ├── evtx_to_jsonl.py    ← Windows Event Log converter
│   └── report.py           ← Markdown report generator
│
├── in/
│   ├── alerts/             ← Drop zone for incoming alert JSON files
│   └── processed/          ← Alerts moved here after pipeline runs
│
└── out/
    ├── cases/              ← Generated case markdown files (case-*.md)
    ├── findings.jsonl      ← Journal of all script runs
    ├── pipeline_log.jsonl  ← Pipeline execution log
    ├── report.md           ← Exported findings report
    └── telemetry/          ← Demo event logs (JSONL)
```

---

## Script Reference

### `dispatch.py`

The main entrypoint. Accepts plain-language analyst input, detects intent via regex, and routes to the correct script.

```bash
python scripts/dispatch.py "CVE-2024-3094"
python scripts/dispatch.py --json "185.220.101.5"   # Print raw JSON
python scripts/dispatch.py --mock "CVE-2024-3094"   # Use mock data
```

### `pipeline.py`

Processes alert files through the full enrich → classify → escalate → bundle chain.

```bash
python scripts/pipeline.py                  # Process all pending alerts once
python scripts/pipeline.py --watch          # Watch in/alerts/ for new files
python scripts/pipeline.py --mock           # Use mock data
```

### `report.py`

Generates a shareable markdown report from the findings journal.

```bash
python scripts/report.py --out out/report.md
```

### `scan_assets.py`

Matches CVE data against your asset inventory to identify exposed hosts.

```bash
python scripts/scan_assets.py "CVE-2021-44228"
```

### All other scripts

Each script accepts the analyst input as a positional argument and prints a JSON object matching the [output contract](#output-contract).

```bash
python scripts/triage.py "INPUT"
python scripts/cve_lookup.py "INPUT"
python scripts/detection_rule.py "INPUT"
python scripts/synthetic_logs.py "INPUT"
python scripts/log_scan.py "PATH_TO_JSONL"
```

All scripts also accept `--mock` to return canned data without making API calls.

---

## Self-Test

Verify all capabilities are wired up correctly:

```bash
python scripts/cve_lookup.py --mock
python scripts/triage.py --mock
python scripts/detection_rule.py --mock
python scripts/synthetic_logs.py --mock
python scripts/dispatch.py --mock "CVE-2024-3094"
```

Each should print a valid JSON object with exactly the four keys: `severity`, `summary`, `mitre`, `action`.

---

## Offline Mode

Set `SECOPS_HUB_OFFLINE=1` to force all scripts to use realistic mock/fallback data with no outbound API calls. Useful for air-gapped networks, demos, or rate-limited environments.

```bash
SECOPS_HUB_OFFLINE=1 python scripts/dispatch.py "CVE-2021-44228"
```

Every script gracefully degrades: a failed API call returns a valid contract object with canned data rather than an error.

---

## Report Export

Generate a shareable markdown report from all journal entries:

```bash
python scripts/report.py --out out/report.md
```

The report aggregates all entries from `out/findings.jsonl` into a formatted document suitable for sharing with stakeholders or attaching to a ticket.

---

## Webhook Integration

To forward every journal entry to an external endpoint (SIEM, ticketing system, Slack webhook):

```
SECOPS_HUB_WEBHOOK_URL=https://your-endpoint.example.com/ingest
```

`dispatch.py` will POST each finding as JSON to that URL after writing to the local journal.
