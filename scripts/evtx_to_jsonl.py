import json
import pathlib
import subprocess
import sys


def _skill_dir() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1]


_EVTX_FIELDS = [
    "TimeCreated",
    "Id",
    "ProviderName",
    "LevelDisplayName",
    "MachineName",
    "UserId",
    "Message",
]


def _convert_evtx(evtx_path):
    ps_script = f"""
$events = Get-WinEvent -Path '{evtx_path}' -MaxEvents 1000 -ErrorAction SilentlyContinue
$events | ForEach-Object {{
    $evt = $_
    $props = @{{
        TimeCreated  = $evt.TimeCreated.ToString('o')
        EventID      = $evt.Id
        Channel      = $evt.ProviderName
        Level        = $evt.LevelDisplayName
        Host         = $evt.MachineName
        User         = $evt.UserId.Value
    }}

    if ($evt.Message) {{
        $props.Message = $evt.Message
    }}

    if ($evt.Properties) {{
        for ($i = 0; $i -lt $evt.Properties.Count; $i++) {{
            $val = $evt.Properties[$i].Value
            if ($val) {{
                $props["Prop_$i"] = $val
            }}
        }}
    }}

    $json = $props | ConvertTo-Json -Compress
    Write-Output $json
}}
"""
    proc = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps_script],
        capture_output=True, text=True, timeout=120,
    )
    events = []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def main():
    if len(sys.argv) < 2:
        result = {
            "severity": "Info",
            "summary": "Usage: python evtx_to_jsonl.py <file.evtx> [output.jsonl]",
            "mitre": "N/A",
            "action": "Provide an EVTX file path to convert."
        }
        print(json.dumps(result, ensure_ascii=False))
        return

    evtx_path = pathlib.Path(sys.argv[1])
    if not evtx_path.exists():
        result = {
            "severity": "Info",
            "summary": f"EVTX file not found: {evtx_path}",
            "mitre": "N/A",
            "action": "Check the path and try again."
        }
        print(json.dumps(result, ensure_ascii=False))
        return

    out_path = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else (evtx_path.parent / (evtx_path.stem + ".jsonl"))

    try:
        events = _convert_evtx(str(evtx_path.resolve()))
    except Exception as e:
        result = {
            "severity": "Info",
            "summary": f"EVTX conversion failed: {e}",
            "mitre": "N/A",
            "action": "Ensure the EVTX file is valid and PowerShell Get-WinEvent can read it."
        }
        print(json.dumps(result, ensure_ascii=False))
        return

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for evt in events:
            f.write(json.dumps(evt, ensure_ascii=False) + "\n")

    result = {
        "severity": "Info",
        "summary": f"Converted {len(events)} events from {evtx_path.name} to {out_path}",
        "mitre": "N/A",
        "action": f"Now scan with: python .trae/skills/secops-hub/scripts/log_scan.py {out_path}"
    }
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
