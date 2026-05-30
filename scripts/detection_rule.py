#!/usr/bin/env python3
"""
detection_rule.py — SecOps Hub capability: generate a Sigma detection rule.

Input : a plain-language attack description, e.g.
        "powershell downloading a file from a suspicious domain"
Output: a single JSON object on stdout matching the SecOps Hub contract:
        { severity, summary, mitre, action }
        (the Sigma YAML lives in `summary`).

No external API. Fully deterministic and offline, so it can never fail the
demo. Inside TRAE the model can ENRICH the rule from the same description;
this template is the guaranteed working baseline.
"""
import sys, json

# Ordered keyword -> template map. First match wins; falls through to generic.
TEMPLATES = [
    {
        "keywords": ("powershell", "invoke-webrequest", "downloadstring", "iex", "encodedcommand"),
        "severity": "High",
        "mitre": "T1059.001 - Command and Scripting Interpreter: PowerShell",
        "title": "Suspicious PowerShell Download / Execution",
        "logsource": "  category: process_creation\n  product: windows",
        "detection": ("  selection:\n"
                      "    Image|endswith: '\\powershell.exe'\n"
                      "    CommandLine|contains:\n"
                      "      - 'DownloadString'\n"
                      "      - 'Invoke-WebRequest'\n"
                      "      - 'EncodedCommand'\n"
                      "      - 'http'\n"
                      "  condition: selection"),
    },
    {
        "keywords": ("mimikatz", "lsass", "credential dump", "sekurlsa", "comsvcs"),
        "severity": "Critical",
        "mitre": "T1003.001 - OS Credential Dumping: LSASS Memory",
        "title": "Possible LSASS Credential Dumping",
        "logsource": "  category: process_access\n  product: windows",
        "detection": ("  selection:\n"
                      "    TargetImage|endswith: '\\lsass.exe'\n"
                      "    GrantedAccess|contains:\n"
                      "      - '0x1010'\n"
                      "      - '0x1410'\n"
                      "  condition: selection"),
    },
    {
        "keywords": ("rdp", "remote desktop", "3389", "brute force", "failed logon"),
        "severity": "Medium",
        "mitre": "T1110 - Brute Force",
        "title": "RDP Brute Force - Repeated Failed Logons",
        "logsource": "  product: windows\n  service: security",
        "detection": ("  selection:\n"
                      "    EventID: 4625\n"
                      "    LogonType: 10\n"
                      "  timeframe: 5m\n"
                      "  condition: selection | count() by SourceIp > 10"),
    },
    {
        "keywords": ("dns", "exfiltration", "tunnel", "beacon", "c2", "long query"),
        "severity": "High",
        "mitre": "T1071.004 - Application Layer Protocol: DNS",
        "title": "Suspicious DNS - Possible Tunneling / C2",
        "logsource": "  category: dns_query\n  product: windows",
        "detection": ("  selection:\n"
                      "    QueryName|re: '.{50,}'\n"
                      "  condition: selection"),
    },
]

GENERIC = {
    "severity": "Medium",
    "mitre": "T1059 - Command and Scripting Interpreter",
    "title": "Suspicious Process Activity - Auto-generated",
    "logsource": "  category: process_creation\n  product: windows",
    "detection": ("  selection:\n"
                  "    CommandLine|contains:\n"
                  "      - 'http'\n"
                  "      - 'cmd /c'\n"
                  "      - 'powershell'\n"
                  "  condition: selection"),
}


def pick(description):
    low = description.lower()
    for t in TEMPLATES:
        if any(k in low for k in t["keywords"]):
            return t
    return GENERIC


def make_rule(description):
    t = pick(description)
    sigma = (
        f"title: {t['title']}\n"
        f"status: experimental\n"
        f"description: 'Auto-generated for: {description[:80]}'\n"
        f"logsource:\n{t['logsource']}\n"
        f"detection:\n{t['detection']}\n"
        f"level: {t['severity'].lower()}"
    )
    return {
        "severity": t["severity"],
        "summary": sigma,
        "mitre": t["mitre"],
        "action": ("Deploy to your SIEM as experimental, tune out false positives against "
                   "a baseline, then promote to alerting.")
    }


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--mock":
        print(json.dumps(make_rule("powershell downloading a file from a suspicious domain"), ensure_ascii=False))
        return
    desc = " ".join(sys.argv[1:]) or "powershell downloading a file from a suspicious domain"
    print(json.dumps(make_rule(desc), ensure_ascii=False))


if __name__ == "__main__":
    main()
