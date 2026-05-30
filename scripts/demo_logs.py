import argparse
import datetime as dt
import json
import pathlib
import random
import sys


def _skill_dir() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1]


def _default_out() -> pathlib.Path:
    return _skill_dir() / "out" / "telemetry" / "demo_events.jsonl"


def _ts(i: int) -> str:
    base = dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=10)
    return (base + dt.timedelta(seconds=i * 3)).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _benign_events(n: int) -> list[dict]:
    procs = [
        r"C:\Windows\System32\svchost.exe",
        r"C:\Windows\System32\conhost.exe",
        r"C:\Windows\explorer.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    ]
    hosts = ["WORKSTATION01", "WORKSTATION02", "APP01"]
    users = ["CORP\\alice", "CORP\\bob", "NT AUTHORITY\\SYSTEM"]

    out: list[dict] = []
    for i in range(n):
        out.append(
            {
                "TimeCreated": _ts(i),
                "EventID": 4688,
                "Channel": "Security",
                "Image": random.choice(procs),
                "CommandLine": "",
                "User": random.choice(users),
                "Host": random.choice(hosts),
            }
        )
    return out


def _events_powershell_download() -> list[dict]:
    return [
        {
            "TimeCreated": _ts(100),
            "EventID": 4688,
            "Channel": "Security",
            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "CommandLine": r"powershell.exe -NoP -W Hidden -EncodedCommand <base64>",
            "User": "CORP\\alice",
            "Host": "WORKSTATION01",
        },
        {
            "TimeCreated": _ts(101),
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
            "TimeCreated": _ts(200),
            "EventID": 4688,
            "Channel": "Security",
            "Image": r"C:\Users\Public\mimikatz.exe",
            "CommandLine": r"mimikatz.exe \"sekurlsa::logonpasswords\" exit",
            "User": "CORP\\alice",
            "Host": "WORKSTATION01",
        },
        {
            "TimeCreated": _ts(201),
            "EventID": 10,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "SourceImage": r"C:\Users\Public\mimikatz.exe",
            "TargetImage": r"C:\Windows\System32\lsass.exe",
            "GrantedAccess": "0x1410",
            "Host": "WORKSTATION01",
        },
    ]


def _write_jsonl(path: pathlib.Path, events: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--out", type=str, default="")
    parser.add_argument("--scenario", type=str, default="both")
    ns = parser.parse_args()

    scenario = (ns.scenario or "both").strip().lower()
    if scenario not in {"both", "mimikatz", "powershell"}:
        scenario = "both"

    events: list[dict] = []
    events.extend(_benign_events(30))
    if scenario in {"both", "powershell"}:
        events.extend(_events_powershell_download())
    if scenario in {"both", "mimikatz"}:
        events.extend(_events_mimikatz_lsass())

    out_path = pathlib.Path(ns.out) if (ns.out or "").strip() else _default_out()
    _write_jsonl(out_path, events)

    summary = f"Wrote {len(events)} events to {out_path.as_posix()}"
    res = {
        "severity": "Info",
        "summary": summary,
        "mitre": "N/A",
        "action": f"Scan it with: python .trae/skills/secops-hub/scripts/log_scan.py \"{out_path.as_posix()}\"",
    }
    sys.stdout.write(json.dumps(res, ensure_ascii=False))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
