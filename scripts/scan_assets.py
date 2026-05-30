import csv
import json
import pathlib
import subprocess
import sys


_VULN_PRODUCT_MAP = {
    "CVE-2021-44228": {"product": "log4j", "range": "2.0-beta9 to 2.15.0", "fixed": "2.17.0"},
    "CVE-2024-3094":  {"product": "xz",     "range": "5.6.0 to 5.6.1",    "fixed": "5.6.2"},
    "CVE-2024-6387":  {"product": "openssh", "range": "8.5p1 to 9.8p1",  "fixed": "9.8p1"},
}


def _skill_dir() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1]


def _assets_path() -> pathlib.Path:
    return _skill_dir() / "assets.csv"


def _load_assets() -> list[dict]:
    p = _assets_path()
    if not p.exists():
        return []
    rows = []
    with p.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append({k.strip().lower(): v.strip() for k, v in row.items()})
    return rows


def _match_assets(cve_id, vuln_info):
    assets = _load_assets()
    if not assets or not vuln_info:
        return []
    target_product = vuln_info.get("product", "").lower()
    if not target_product:
        return []
    matched = []
    for a in assets:
        if a.get("product", "").lower() == target_product:
            a["_status"] = "potentially vulnerable"
            a["_cve_range"] = vuln_info.get("range", "unknown")
            a["_cve_fixed"] = vuln_info.get("fixed", "unknown")
            matched.append(a)
    return matched


def _run_cve_lookup(cve_id):
    script = _skill_dir() / "scripts" / "cve_lookup.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--mock", cve_id],
        cwd=str(_skill_dir()),
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return None
    return json.loads((proc.stdout or "").strip())


def main():
    text = " ".join(sys.argv[1:]).strip() if len(sys.argv) > 1 else "CVE-2021-44228"

    import re
    cve_match = re.search(r"\bCVE-\d{4}-\d{4,}\b", text, re.IGNORECASE)
    cve_id = cve_match.group(0).upper() if cve_match else text.upper()

    vuln_info = _VULN_PRODUCT_MAP.get(cve_id)

    cve_result = _run_cve_lookup(cve_id) if vuln_info else None

    affected = _match_assets(cve_id, vuln_info) if vuln_info else []

    if not vuln_info:
        result = {
            "severity": "Info",
            "summary": f"{cve_id} is not in the known product vulnerability map. Run a CVE lookup first to identify the affected product, then update VULN_PRODUCT_MAP in scan_assets.py.",
            "mitre": "N/A",
            "action": f"Look up the CVE: python .trae/skills/secops-hub/scripts/dispatch.py '{cve_id}'. Then add it to scan_assets.py."
        }
    elif not affected:
        sev = cve_result.get("severity", "Info") if cve_result else "Info"
        result = {
            "severity": sev,
            "summary": f"{cve_id} affects {vuln_info['product']} (versions {vuln_info['range']}). No matching assets found in assets.csv — your environment appears safe.",
            "mitre": cve_result.get("mitre", "N/A") if cve_result else "N/A",
            "action": "Verify your assets.csv is complete. If you do run this product, add it and rescan."
        }
    else:
        names = [a.get("name", "?") for a in affected]
        envs = [f"{a.get('name','?')} ({a.get('environment','?')}/{a.get('exposure','?')})" for a in affected]
        sev = cve_result.get("severity", "Critical") if cve_result else "Critical"
        result = {
            "severity": sev,
            "summary": f"{cve_id} affects {vuln_info['product']} ({vuln_info['range']}, fixed in {vuln_info['fixed']}). AFFECTED: {', '.join(names)} ({len(affected)} assets)",
            "mitre": cve_result.get("mitre", "N/A") if cve_result else "N/A",
            "action": f"Affected: {', '.join(envs)}. Patch {vuln_info['product']} to {vuln_info['fixed']} or later on all affected assets immediately."
        }

    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
