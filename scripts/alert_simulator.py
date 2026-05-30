import argparse
import datetime as dt
import json
import os
import pathlib
import random
import sys


_ALERT_TEMPLATES = [
    {
        "type": "credential-dump",
        "title": "Possible LSASS Credential Dumping",
        "severity": "Critical",
        "source": "EDR",
        "raw_text": "Suspicious process mimikatz.exe accessed lsass.exe with GrantedAccess 0x1410 on WORKSTATION01.",
        "iocs": {
            "ip": ["185.220.101.34"],
            "domain": ["c2-malware.example.com"],
            "sha256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
        },
        "keywords": ["mimikatz", "lsass", "credential dump", "sekurlsa"]
    },
    {
        "type": "phishing",
        "title": "Suspicious Phishing Email Link Clicked",
        "severity": "High",
        "source": "Email Gateway",
        "raw_text": "User CORP\\bob clicked a link in an email from 'payments@secure-login-update.com' to http://phish-login.example.com/verify.",
        "iocs": {
            "domain": ["phish-login.example.com", "secure-login-update.com"],
            "url": ["http://phish-login.example.com/verify"],
            "ip": ["203.0.113.45"],
        },
        "keywords": ["phish", "credential", "login"]
    },
    {
        "type": "malware",
        "title": "Suspicious PowerShell Download Detected",
        "severity": "High",
        "source": "SIEM",
        "raw_text": "Process powershell.exe on SRV-DC01 executed Invoke-WebRequest http://payload.example.com/agent.exe and saved to C:\\Users\\Public\\agent.exe.",
        "iocs": {
            "domain": ["payload.example.com"],
            "url": ["http://payload.example.com/agent.exe"],
            "sha256": ["d2c8a1f3b76e4d90c5a4e3b2f1a6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3"],
            "md5": ["a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"],
        },
        "keywords": ["powershell", "download", "invoke-webrequest", "malware", "dropper"]
    },
    {
        "type": "brute-force",
        "title": "RDP Brute Force — Repeated Failed Logons",
        "severity": "Medium",
        "source": "SIEM",
        "raw_text": "EventID 4625 repeated 45 times from SourceIp 198.51.100.77 targeting SRV-DC01 via RDP (LogonType 10) in 5 minutes.",
        "iocs": {
            "ip": ["198.51.100.77"],
        },
        "keywords": ["rdp", "brute force", "failed logon", "4625"]
    },
    {
        "type": "c2-beacon",
        "title": "DNS C2 Beaconing Detected",
        "severity": "High",
        "source": "SIEM",
        "raw_text": "Host WORKSTATION02 beaconing to c2-beacon.evil-hackers.com every 60 seconds with long DNS query strings over 100 characters.",
        "iocs": {
            "domain": ["c2-beacon.evil-hackers.com"],
            "ip": ["10.99.88.77"],
        },
        "keywords": ["c2", "beacon", "dns", "command and control", "tunnel"]
    },
    {
        "type": "benign-test",
        "title": "IT Admin Running Scheduled Backup",
        "severity": "Info",
        "source": "SIEM",
        "raw_text": "Process backup.exe executed by CORP\\admin on SRV-BACKUP01. Parent process is scheduled_task.exe. This is a known scheduled backup job.",
        "iocs": {
            "ip": ["10.0.0.50"],
            "domain": ["backup-repo.internal.corp.com"],
        },
        "keywords": ["backup", "scheduled", "admin"]
    },
    {
        "type": "benign-test",
        "title": "DevOps Deploying New Build",
        "severity": "Info",
        "source": "SIEM",
        "raw_text": "Jenkins CI pipeline deploying build to SRV-APP03. Outbound HTTPS to github.com and npmjs.org. Authorized user CORP\\devops.",
        "iocs": {
            "domain": ["github.com", "npmjs.org"],
            "url": ["https://github.com/corp/app/releases", "https://registry.npmjs.org/express"],
        },
        "keywords": ["deploy", "jenkins", "ci", "build"]
    },
    {
        "type": "ransomware",
        "title": "Possible Ransomware — Mass File Renames",
        "severity": "Critical",
        "source": "EDR",
        "raw_text": "Files on SRV-FILE01 being renamed with .encrypted extension. Process encrypt.exe from C:\\Users\\Public\\ with parent process wscript.exe executed suspicious VBS macro. File writes to shadow copies detected.",
        "iocs": {
            "sha256": ["f1e2d3c4b5a69788796a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4"],
            "domain": ["ransom-c2.tor-exit.example"],
            "ip": ["45.33.32.156"],
        },
        "keywords": ["ransomware", "encrypt", ".encrypted", "shadow", "extortion"]
    },
]


def _skill_dir() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1]


def _alerts_dir() -> pathlib.Path:
    return _skill_dir() / "in" / "alerts"


def main():
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--count", type=int, default=5)
    parser.add_argument("--seed", type=int, default=0)
    ns = parser.parse_args()

    if ns.seed:
        random.seed(ns.seed)

    count = max(1, min(ns.count, len(_ALERT_TEMPLATES)))
    templates = random.sample(_ALERT_TEMPLATES, count)

    out_dir = _alerts_dir()
    out_dir.mkdir(parents=True, exist_ok=True)

    ts = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    results = []

    for i, tmpl in enumerate(templates):
        alert_id = f"alert-{ts.strftime('%Y%m%d-%H%M%S')}-{i+1:04d}"
        ts_offset = ts - dt.timedelta(minutes=random.randint(0, 120))
        alert = {
            "id": alert_id,
            "timestamp": ts_offset.isoformat().replace("+00:00", "Z"),
            "type": tmpl["type"],
            "title": tmpl["title"],
            "severity": tmpl["severity"],
            "source": tmpl["source"],
            "raw_text": tmpl["raw_text"],
            "iocs": tmpl["iocs"],
            "keywords": tmpl["keywords"],
        }
        file_path = out_dir / f"{alert_id}.json"
        file_path.write_text(json.dumps(alert, indent=2, ensure_ascii=False), encoding="utf-8")
        results.append(str(file_path))

    print(json.dumps({
        "severity": "Info",
        "summary": f"Generated {len(results)} alerts into {out_dir}",
        "mitre": "N/A",
        "action": f"Run pipeline: python .trae/skills/secops-hub/scripts/pipeline.py --once to process them."
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
