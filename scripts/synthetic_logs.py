import argparse
import json
import re


def _events_powershell_download() -> list[dict]:
    return [
        {
            "EventID": 4688,
            "Channel": "Security",
            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "CommandLine": r"powershell.exe -NoP -W Hidden -EncodedCommand <base64>",
            "User": "WORKSTATION\\user1",
            "Host": "WORKSTATION01",
        },
        {
            "EventID": 3,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "DestinationHostname": "suspicious.example",
            "DestinationIp": "203.0.113.50",
            "DestinationPort": 443,
            "Protocol": "tcp",
            "Host": "WORKSTATION01",
        },
    ]


def _events_mimikatz_lsass() -> list[dict]:
    return [
        {
            "EventID": 4688,
            "Channel": "Security",
            "Image": r"C:\Users\Public\mimikatz.exe",
            "CommandLine": r"mimikatz.exe \"sekurlsa::logonpasswords\" exit",
            "User": "WORKSTATION\\user1",
            "Host": "WORKSTATION01",
        },
        {
            "EventID": 10,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "SourceImage": r"C:\Users\Public\mimikatz.exe",
            "TargetImage": r"C:\Windows\System32\lsass.exe",
            "GrantedAccess": "0x1410",
            "Host": "WORKSTATION01",
        },
    ]


def _pick(text: str) -> tuple[str, str, list[dict]]:
    t = (text or "").lower()
    if any(k in t for k in ["mimikatz", "lsass", "sekurlsa", "credential dump", "dumping"]):
        return (
            "High",
            "T1003.001 - OS Credential Dumping: LSASS Memory",
            _events_mimikatz_lsass(),
        )
    return (
        "Medium",
        "T1059.001 - Command and Scripting Interpreter: PowerShell",
        _events_powershell_download(),
    )


def _jsonl(events: list[dict]) -> str:
    return "\n".join(json.dumps(e, ensure_ascii=False) for e in events)


def main() -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--mock", action="store_true")
    parser.add_argument("text", nargs="*", default=[])
    ns = parser.parse_args()

    text = " ".join(ns.text).strip()
    if not text:
        text = "powershell downloading a file from a suspicious domain"

    severity, mitre, events = _pick(text)
    summary = _jsonl(events)
    action = "Ingest these JSONL events into your demo index and run the generated detection rule against them."

    out = {"severity": severity, "summary": summary, "mitre": mitre, "action": action}
    for k in ("severity", "summary", "mitre", "action"):
        if k not in out:
            raise SystemExit(2)
    print(json.dumps(out, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
