import argparse
import datetime as dt
import json
import os
import pathlib
import re
import subprocess
import sys
import urllib.request


_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_DEMO_LOGS_RE = re.compile(r"\b(generate|create|make)\b.*\b(demo\s+)?(logs?|events?)\b", re.IGNORECASE)
_DEMO_ALERTS_RE = re.compile(r"\b(generate|create|make)\b.*\b(demo\s+)?(alert|incident|case)s?\b", re.IGNORECASE)
_SCAN_LOGS_RE = re.compile(r"\b(scan|analy[sz]e|hunt)\b.*\b(logs?|events?|jsonl|evtx)\b|\.jsonl\b", re.IGNORECASE)
_SCAN_ASSETS_RE = re.compile(r"\b(scan|check|match)\b.*\b(asset|inventory|cpe)\b|assets?\s*(against|for|with)\b", re.IGNORECASE)
_CONVERT_EVTX_RE = re.compile(r"\b(convert|transform)\b.*\b(evtx|event\s*log)\b", re.IGNORECASE)
_PIPELINE_RE = re.compile(r"\b(pipeline|process|triage)\b.*\b(alerts?|queue|pending|all|inbox)\b", re.IGNORECASE)
_RULE_RE = re.compile(
    r"\b(rule|sigma|detection|alert|powershell|mimikatz|lsass|sekurlsa|downloadstring|invoke-webrequest|encodedcommand|c2|beacon)\b",
    re.IGNORECASE,
)


def _skill_dir() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1]


def _scripts_dir() -> pathlib.Path:
    return _skill_dir() / "scripts"


def _journal_path() -> pathlib.Path:
    return _skill_dir() / "out" / "findings.jsonl"


def _dotenv_path() -> pathlib.Path:
    return _skill_dir() / ".env"

def _workspace_dir() -> pathlib.Path:
    return _skill_dir().parents[2]


def _load_dotenv(path: pathlib.Path) -> None:
    if not path.exists():
        return
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        return
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip().strip('"').strip("'")
        if not k:
            continue
        if not v:
            continue
        os.environ.setdefault(k, v)


def _should_offline(cli_offline: bool) -> bool:
    if cli_offline:
        return True
    v = (os.environ.get("SECOPS_HUB_OFFLINE") or "").strip().lower()
    return v in {"1", "true", "yes", "y", "on"}


def _pick_capability(text: str) -> str:
    if _SCAN_LOGS_RE.search(text):
        return "log_scan"
    if _DEMO_LOGS_RE.search(text):
        return "demo_logs"
    if _DEMO_ALERTS_RE.search(text):
        return "alert_simulator"
    if _PIPELINE_RE.search(text):
        return "pipeline"
    if _SCAN_ASSETS_RE.search(text):
        return "scan_assets"
    if _CONVERT_EVTX_RE.search(text):
        return "evtx_to_jsonl"
    if _CVE_RE.search(text):
        return "cve_lookup"
    if _RULE_RE.search(text):
        return "detection_rule"
    return "triage"


def _extract_path_arg(text: str) -> str:
    toks = [t.strip("\"'") for t in (text or "").split() if t.strip()]
    for t in toks:
        if t.lower().endswith(".jsonl"):
            return t
    for t in toks:
        if t.lower().endswith(("\\.jsonl",)):
            return t
    for t in toks:
        if any(x in t.lower() for x in ["out/", "out\\", ".trae/", ".trae\\"]):
            return t
    return ""


def _normalize_path_arg(p: str) -> str:
    s = (p or "").strip().strip("\"'")
    if not s:
        return ""
    candidate = pathlib.Path(s)
    if candidate.is_absolute():
        return str(candidate)
    if s.startswith(".trae") or s.startswith(".trae/") or s.startswith(".trae\\"):
        return str(_workspace_dir() / s)
    return str((_skill_dir() / s).resolve())


def _run_script(script_name: str, args: list[str]) -> dict:
    script_path = _scripts_dir() / f"{script_name}.py"
    proc = subprocess.run(
        [sys.executable, str(script_path), *args],
        cwd=str(_skill_dir()),
        capture_output=True,
        text=True,
    )
    out = (proc.stdout or "").strip()
    if proc.returncode != 0:
        err = (proc.stderr or "").strip()
        raise RuntimeError(f"{script_name} exited {proc.returncode}: {err}")
    try:
        obj = json.loads(out)
    except Exception as e:
        raise RuntimeError(f"{script_name} output is not valid JSON: {e}") from e
    for k in ("severity", "summary", "mitre", "action"):
        if k not in obj:
            raise RuntimeError(f"{script_name} JSON missing key: {k}")
    return obj


def _append_journal(entry: dict) -> None:
    p = _journal_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _post_webhook(url: str, payload: dict) -> None:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()


_CAP_TITLES = {
    "cve_lookup":       "CVE Lookup",
    "detection_rule":   "Detection Rule",
    "triage":           "IOC Triage",
    "demo_logs":        "Demo Logs",
    "log_scan":         "Log Scan",
    "alert_simulator":  "Alert Simulator",
    "pipeline":         "AI SOC Pipeline",
    "scan_assets":      "Asset Vulnerability Scan",
    "evtx_to_jsonl":    "EVTX Converter",
}

_SEV_LABELS = {
    "Critical": "[CRITICAL]",
    "High":     "[HIGH]",
    "Medium":   "[MEDIUM]",
    "Low":      "[LOW]",
    "Info":     "[INFO]",
}


def _wrap(text: str, width: int) -> list[str]:
    lines: list[str] = []
    for word in text.split():
        if lines and len(lines[-1]) + 1 + len(word) <= width:
            lines[-1] += " " + word
        else:
            lines.append(word)
    return lines or [""]


def _render_human(result: dict, capability: str = "") -> str:
    sev     = str(result.get("severity", "")).strip()
    mitre   = str(result.get("mitre",    "")).strip()
    summary = str(result.get("summary", "")).strip()
    action  = str(result.get("action",  "")).strip()

    title = _CAP_TITLES.get(capability, "SecOps Hub")
    width = 56
    inner = width - 2          # usable chars between borders

    border  = "+" + "-" * width + "+"
    cap_str = f"  SecOps Hub >> {title}"
    title_line = "|" + cap_str + " " * (width - len(cap_str)) + "|"

    sev_badge = _SEV_LABELS.get(sev, f"[{sev}]")
    divider   = "  " + "-" * inner

    lines: list[str] = [
        "",
        border,
        title_line,
        border,
        "",
        f"  Severity   {sev_badge}",
        f"  MITRE      {mitre}",
        "",
    ]

    if "title:" in summary and "detection:" in summary:
        lines.append("  Sigma Rule")
        lines.append(divider)
        for row in summary.splitlines():
            lines.append(f"  {row}")
    elif "\n" in summary and summary.lstrip().startswith('{"EventID"'):
        lines.append("  Synthetic Events (JSONL)")
        lines.append(divider)
        for row in summary.splitlines():
            lines.append(f"  {row}")
    else:
        lines.append("  Summary")
        lines.append(divider)
        for row in _wrap(summary, inner - 2):
            lines.append(f"  {row}")

    lines += [
        "",
        "  Action",
        divider,
    ]
    for row in _wrap(action, inner - 2):
        lines.append(f"  {row}")

    lines.append("")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--mock", action="store_true")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--webhook", type=str, default="")
    parser.add_argument("--json", action="store_true", dest="raw_json",
                        help="Output raw JSON instead of the formatted report")
    parser.add_argument("--human", action="store_true",
                        help="(deprecated alias for default behaviour; kept for compatibility)")
    parser.add_argument("text", nargs="*", default=[])
    ns = parser.parse_args()

    _load_dotenv(_dotenv_path())

    text = " ".join(ns.text).strip()
    if not text:
        text = "CVE-2024-3094"

    cap = _pick_capability(text)
    offline = _should_offline(ns.offline)

    try:
        if cap == "cve_lookup":
            cve = _CVE_RE.search(text).group(0) if _CVE_RE.search(text) else text
            argv = ["--mock"] if (ns.mock or offline) else []
            argv.append(cve)
            result = _run_script("cve_lookup", argv)
        elif cap == "detection_rule":
            argv = ["--mock"] if ns.mock else []
            if not ns.mock:
                argv.append(text)
            result = _run_script("detection_rule", argv)
        elif cap == "demo_logs":
            argv = []
            if not ns.mock:
                argv.append("--scenario")
                argv.append("both")
            result = _run_script("demo_logs", argv)
        elif cap == "log_scan":
            p = _extract_path_arg(text)
            argv = []
            if p:
                argv.append(_normalize_path_arg(p))
            result = _run_script("log_scan", argv)
        elif cap == "alert_simulator":
            argv = []
            if not ns.mock:
                argv.append("--count")
                argv.append("5")
            result = _run_script("alert_simulator", argv)
        elif cap == "pipeline":
            argv = ["--once", "--json"]
            result = _run_script("pipeline", argv)
        elif cap == "scan_assets":
            cve = _CVE_RE.search(text).group(0) if _CVE_RE.search(text) else text
            argv = [cve]
            result = _run_script("scan_assets", argv)
        elif cap == "evtx_to_jsonl":
            argv_temp = [t.strip('"\'') for t in text.split() if t.lower().endswith(".evtx")]
            if not argv_temp:
                argv_temp = [text]
            argv = argv_temp[:1]
            result = _run_script("evtx_to_jsonl", argv)
        else:
            argv = ["--mock"] if (ns.mock or offline) else []
            if not ns.mock:
                argv.append(text)
            result = _run_script("triage", argv)
    except Exception as e:
        result = {
            "severity": "Info",
            "summary": f"secops-hub dispatch failed: {e}",
            "mitre": "N/A",
            "action": "Rerun with --mock/--offline, and verify the scripts exist and can be executed.",
        }

    entry = {
        "ts": dt.datetime.now(dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "capability": cap,
        "input": text,
        "cwd": str(_skill_dir()),
        "result": result,
    }
    try:
        _append_journal(entry)
    except Exception:
        pass

    webhook = (ns.webhook or "").strip() or (os.environ.get("SECOPS_HUB_WEBHOOK_URL") or "").strip()
    if webhook:
        try:
            _post_webhook(webhook, entry)
        except Exception:
            pass

    if ns.raw_json:
        out_text = json.dumps(result, ensure_ascii=False)
    else:
        out_text = _render_human(result, cap)

    try:
        sys.stdout.write(out_text)
    except UnicodeEncodeError:
        sys.stdout.buffer.write(out_text.encode("utf-8", errors="replace"))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
