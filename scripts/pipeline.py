import datetime as dt
import json
import os
import pathlib
import subprocess
import sys
import time


def _skill_dir() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1]


def _scripts_dir() -> pathlib.Path:
    return _skill_dir() / "scripts"


def _alerts_dir() -> pathlib.Path:
    return _skill_dir() / "in" / "alerts"


def _processed_dir() -> pathlib.Path:
    return _skill_dir() / "in" / "processed"


def _run_py(script_name, *args):
    path = _scripts_dir() / f"{script_name}.py"
    proc = subprocess.run(
        [sys.executable, str(path), *args],
        cwd=str(_skill_dir()),
        capture_output=True, text=True,
    )
    out = (proc.stdout or "").strip()
    if proc.returncode != 0:
        raise RuntimeError(f"{script_name} failed: {(proc.stderr or '').strip()}")
    return json.loads(out)


def _load_dotenv():
    env_path = _skill_dir() / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip().strip('"').strip("'")
        if k and v:
            os.environ.setdefault(k, v)


def _pickup_alerts():
    alerts_dir = _alerts_dir()
    if not alerts_dir.exists():
        return []
    files = sorted(alerts_dir.glob("alert-*.json"))
    return files


def _process_alert(alert_path):
    with open(alert_path, encoding="utf-8") as f:
        alert = json.load(f)

    enriched = _run_py("enrich", str(alert_path))
    classification = _run_py("classify", json.dumps(enriched, ensure_ascii=False))
    escalation = _run_py("escalate", json.dumps({
        "alert": alert,
        "enriched": enriched,
        "classification": classification,
    }, ensure_ascii=False))

    bundle_input = json.dumps({
        "alert": alert,
        "enriched": enriched,
        "classification": classification,
        "escalation": escalation,
    }, ensure_ascii=False)

    bundle_result = _run_py("bundle", bundle_input)

    return {
        "alert": alert,
        "enriched": enriched,
        "classification": classification,
        "escalation": escalation,
        "bundle": bundle_result,
    }


def _move_processed(alert_path):
    dest = _processed_dir()
    dest.mkdir(parents=True, exist_ok=True)
    alert_path.rename(dest / alert_path.name)


def _render_row(result, idx):
    alert = result["alert"]
    classification = result["classification"]
    escalation = result["escalation"]

    sev = alert.get("severity", "?")[:5].ljust(5)
    conf = f"{classification.get('confidence', 0)}%".ljust(5)
    dec = escalation.get("decision", "?")[:10].ljust(10)
    title = alert.get("title", "?")[:45].ljust(45)
    alert_id = alert.get("id", "")[-8:]

    dec_label = dec.strip()
    if dec_label == "escalate":
        dec_label = f">>> {dec_label} <<<"
    elif dec_label == "suppress":
        dec_label = f"    {dec_label}"

    return f"  {idx:3d}  {sev}  {conf}  {dec_label:26s}  {alert_id}  {title}"


def _journal(payload):
    p = _skill_dir() / "out" / "pipeline_log.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "summary": payload,
    }
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _notify_telegram(text):
    token = (os.environ.get("TELEGRAM_BOT_TOKEN") or "").strip()
    chat_id = (os.environ.get("TELEGRAM_CHAT_ID") or "").strip()
    if not token or not chat_id:
        return
    import urllib.request
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    body = json.dumps({
        "chat_id": chat_id,
        "text": text,
        "disable_web_page_preview": True,
    }).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


def main():
    import argparse
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--interval", type=int, default=5)
    ns = parser.parse_args()

    _load_dotenv()

    if ns.once:
        alerts = _pickup_alerts()
        if not alerts:
            if ns.json:
                print(json.dumps({"severity": "Info", "summary": "No pending alerts in in/alerts/.", "mitre": "N/A", "action": "Generate alerts with: python .trae/skills/secops-hub/scripts/dispatch.py --json 'generate demo alerts'"}))
            else:
                print("No pending alerts in in/alerts/.")
            return 0

        if not ns.json:
            print(f"\nProcessing {len(alerts)} alert(s)...\n")
            print("  #    Sev    Conf   Decision                    ID        Title")
            print("  ---  -----  -----  --------------------------  --------  " + "-" * 45)

        results = []
        for i, alert_path in enumerate(alerts, start=1):
            try:
                result = _process_alert(alert_path)
                results.append(result)
                _move_processed(alert_path)
                if not ns.json:
                    print(_render_row(result, i))
                journal_payload = {
                    "alert_id": result["alert"].get("id"),
                    "severity": result["alert"].get("severity"),
                    "confidence": result["classification"].get("confidence"),
                    "decision": result["escalation"].get("decision"),
                    "verdict": result["classification"].get("verdict"),
                }
                _journal(journal_payload)
                if result["escalation"].get("decision") == "escalate":
                    title = result["alert"].get("title", "Alert")
                    sev = result["alert"].get("severity", "?")
                    conf = result["classification"].get("confidence", 0)
                    _notify_telegram(f"[secops-hub] {sev} | {title}\nConfidence: {conf}%\nDecision: ESCALATE")
            except Exception as e:
                if not ns.json:
                    print(f"  {i:3d}  ERROR: {e}")
                _move_processed(alert_path)

        escalated = sum(1 for r in results if r["escalation"].get("decision") == "escalate")
        reviewed = sum(1 for r in results if r["escalation"].get("decision") == "review")
        suppressed = sum(1 for r in results if r["escalation"].get("decision") == "suppress")

        if ns.json:
            print(json.dumps({
                "severity": "Critical" if escalated > 0 else ("High" if reviewed > 0 else "Info"),
                "summary": f"Processed {len(alerts)} alerts | Escalated: {escalated} | Review: {reviewed} | Suppressed: {suppressed} | Cases: out/cases/",
                "mitre": "N/A",
                "action": f"Review escalated cases in out/cases/. Suppressed {suppressed} false positives.",
            }, ensure_ascii=False))
        else:
            print(f"\n  Done.  Escalated: {escalated}  |  Review: {reviewed}  |  Suppressed: {suppressed}")
            print(f"  Cases written to: {_skill_dir() / 'out' / 'cases'}\n")
        return 0

    if ns.watch:
        print(f"\nWatching {_alerts_dir()} for new alerts (Ctrl+C to stop)...\n")
        print("  #    Sev    Conf   Decision                    ID        Title")
        print("  ---  -----  -----  --------------------------  --------  " + "-" * 45)
        count = 0
        seen = set()
        try:
            while True:
                alerts = _pickup_alerts()
                new_alerts = [a for a in alerts if a.name not in seen]
                for alert_path in new_alerts:
                    seen.add(alert_path.name)
                    count += 1
                    try:
                        result = _process_alert(alert_path)
                        _move_processed(alert_path)
                        print(_render_row(result, count))
                        journal_payload = {
                            "alert_id": result["alert"].get("id"),
                            "severity": result["alert"].get("severity"),
                            "confidence": result["classification"].get("confidence"),
                            "decision": result["escalation"].get("decision"),
                            "verdict": result["classification"].get("verdict"),
                        }
                        _journal(journal_payload)
                        if result["escalation"].get("decision") == "escalate":
                            title = result["alert"].get("title", "Alert")
                            sev = result["alert"].get("severity", "?")
                            conf = result["classification"].get("confidence", 0)
                            _notify_telegram(f"[secops-hub] {sev} | {title}\nConfidence: {conf}%\nDecision: ESCALATE")
                    except Exception as e:
                        print(f"  {count:3d}  ERROR: {e}")
                        _move_processed(alert_path)
                time.sleep(ns.interval)
        except KeyboardInterrupt:
            print("\nStopped.\n")
        return 0

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
