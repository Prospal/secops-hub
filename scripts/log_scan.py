import argparse
import json
import pathlib
import sys


def _skill_dir() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1]


def _iter_jsonl_files(p: pathlib.Path) -> list[pathlib.Path]:
    if p.is_file():
        return [p]
    if p.is_dir():
        return sorted([x for x in p.rglob("*.jsonl") if x.is_file()])
    return []


def _read_jsonl(path: pathlib.Path) -> list[dict]:
    out: list[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out


def _is_powershell(image: str) -> bool:
    return (image or "").lower().endswith("\\powershell.exe")


def _hit_powershell_download(evt: dict) -> bool:
    image = str(evt.get("Image", "") or "")
    cmd = str(evt.get("CommandLine", "") or "")
    if evt.get("EventID") == 4688 and _is_powershell(image):
        low = cmd.lower()
        return any(k in low for k in ["downloadstring", "invoke-webrequest", "encodedcommand", "http://", "https://"])
    if evt.get("EventID") == 3 and _is_powershell(image):
        return True
    return False


def _hit_lsass_dump(evt: dict) -> bool:
    target = str(evt.get("TargetImage", "") or "")
    access = str(evt.get("GrantedAccess", "") or "")
    if evt.get("EventID") == 10 and target.lower().endswith("\\lsass.exe"):
        return access.lower() in {"0x1010", "0x1410", "0x143a", "0x1fffff"}
    image = str(evt.get("Image", "") or "")
    cmd = str(evt.get("CommandLine", "") or "")
    if evt.get("EventID") == 4688:
        low = (image + " " + cmd).lower()
        return any(k in low for k in ["mimikatz", "sekurlsa::logonpasswords", "comsvcs.dll"])
    return False


def _brief(evt: dict) -> dict:
    keys = [
        "TimeCreated",
        "EventID",
        "Channel",
        "Host",
        "User",
        "Image",
        "SourceImage",
        "TargetImage",
        "CommandLine",
        "DestinationHostname",
        "DestinationIp",
        "DestinationPort",
        "GrantedAccess",
    ]
    out: dict = {}
    for k in keys:
        v = evt.get(k)
        if v is None or v == "":
            continue
        out[k] = v
    return out


def _fmt_counts(counts: dict[str, int]) -> str:
    parts = [f"{k}={v}" for k, v in counts.items() if v]
    return " | ".join(parts) if parts else "no hits"


def main() -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--max", type=int, default=3)
    parser.add_argument("path", nargs="?", default="")
    ns = parser.parse_args()

    path = pathlib.Path(ns.path) if (ns.path or "").strip() else (_skill_dir() / "out" / "telemetry")
    files = _iter_jsonl_files(path)
    if not files:
        res = {
            "severity": "Info",
            "summary": f"No .jsonl files found at {path.as_posix()}",
            "mitre": "N/A",
            "action": "Generate demo logs with: python .trae/skills/secops-hub/scripts/demo_logs.py",
        }
        sys.stdout.write(json.dumps(res, ensure_ascii=False))
        sys.stdout.flush()
        return 0

    total = 0
    hits_ps = 0
    hits_lsass = 0
    sample_ps: list[dict] = []
    sample_lsass: list[dict] = []

    for f in files:
        events = _read_jsonl(f)
        total += len(events)
        for e in events:
            if _hit_powershell_download(e):
                hits_ps += 1
                if len(sample_ps) < ns.max:
                    sample_ps.append(e)
            if _hit_lsass_dump(e):
                hits_lsass += 1
                if len(sample_lsass) < ns.max:
                    sample_lsass.append(e)

    sev = "Info"
    mitre = "N/A"
    if hits_lsass > 0:
        sev = "Critical"
        mitre = "T1003.001 - OS Credential Dumping: LSASS Memory"
    elif hits_ps > 0:
        sev = "High"
        mitre = "T1059.001 - Command and Scripting Interpreter: PowerShell"

    counts = {"powershell_download": hits_ps, "lsass_dump": hits_lsass}
    summary = f"scanned_files={len(files)} | scanned_events={total} | hits: {_fmt_counts(counts)}"
    if sample_lsass:
        summary += " | sample_lsass=" + json.dumps([_brief(e) for e in sample_lsass[: ns.max]], ensure_ascii=False)
    elif sample_ps:
        summary += " | sample_powershell=" + json.dumps([_brief(e) for e in sample_ps[: ns.max]], ensure_ascii=False)

    if sev == "Critical":
        action = "Treat as potential credential dumping. Isolate affected host(s), collect triage artifacts, and hunt for lateral movement."
    elif sev == "High":
        action = "Review PowerShell activity, block suspicious domains, and validate whether the download executed on endpoints."
    else:
        action = "No high-signal detections found. Expand coverage (Sysmon EventID 1/3/10, Security 4688) and rerun with more logs."

    res = {"severity": sev, "summary": summary, "mitre": mitre, "action": action}
    sys.stdout.write(json.dumps(res, ensure_ascii=False))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
