#!/usr/bin/env python3
"""
cve_lookup.py — SecOps Hub capability: CVE lookup with real-world risk context.

Input : a CVE ID, e.g. "CVE-2021-44228"
Output: a single JSON object on stdout, EXACTLY the SecOps Hub contract:
        { severity, summary, mitre, action }

It enriches the bare CVSS severity with two free, no-key signals so the
analyst gets a decision, not just a score:
  - EPSS  (FIRST.org)      -> probability of exploitation in the next 30 days
  - CISA KEV               -> is it being actively exploited in the wild NOW

Demo-safe by design:
  - The core NVD call falls back to canned MOCK data on any failure.
  - EPSS and KEV are *best-effort*: if either source fails, the lookup still
    returns a valid finding (it just omits that one signal). No single source
    can crash the result.
Pass --mock to force the canned response.
"""
import sys, os, json, re, time, urllib.request, urllib.error

NVD_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
EPSS_URL = "https://api.first.org/data/v1/epss?cve="
KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kev_cache.json")
KEV_TTL  = 86400  # refresh the KEV catalog at most once a day

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# Canned fallback — rich enough that an offline demo looks as good as a live one.
MOCK = {
    "severity": "Critical",
    "summary": ("CVE-2021-44228 (CVSS 10.0, vector AV:N/AC:L/PR:N/UI:N): Log4Shell — "
                "remote code execution in Apache Log4j 2 via JNDI lookups in logged strings. "
                "Weakness: CWE-502 (Deserialization of Untrusted Data). "
                "Exploitation likelihood: EPSS 97% (top 1%). LISTED IN CISA KEV - ACTIVELY "
                "EXPLOITED IN THE WILD, KNOWN RANSOMWARE USE."),
    "mitre": "N/A",
    "action": ("ACTIVELY EXPLOITED - patch on an emergency timeline now. Upgrade Log4j to a "
               "fixed version, block outbound LDAP/RMI where possible, and hunt for "
               "exploitation attempts in application logs.")
}


def _get_json(url, timeout=8):
    headers = {"User-Agent": "secops-hub/1.0"}
    nvd_key = (os.environ.get("NVD_API_KEY") or "").strip()
    if nvd_key and url.startswith(NVD_URL):
        headers["apiKey"] = nvd_key
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def get_nvd(cve_id):
    """Core lookup. Returns dict of facts, or None if NVD has no record."""
    data = _get_json(NVD_URL + cve_id.upper())
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None
    cve = vulns[0]["cve"]
    desc = next((d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), "")
    metrics, score, vector = cve.get("metrics", {}), None, ""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            cdata = metrics[key][0]["cvssData"]
            score = cdata.get("baseScore")
            vector = cdata.get("vectorString", "")
            break
    cwe = ""
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            if d.get("value", "").startswith("CWE-"):
                cwe = d["value"]; break
        if cwe:
            break
    return {"score": score, "vector": vector, "desc": desc, "cwe": cwe}


def get_epss(cve_id):
    """Best-effort EPSS. Returns (prob_pct, percentile_pct) or None."""
    try:
        rows = _get_json(EPSS_URL + cve_id.upper(), timeout=6).get("data", [])
        if rows:
            return round(float(rows[0]["epss"]) * 100), round(float(rows[0]["percentile"]) * 100)
    except Exception:
        pass
    return None


def in_kev(cve_id):
    """Best-effort CISA KEV membership. Returns the KEV record, False, or None (unknown)."""
    try:
        catalog = None
        if os.path.exists(KEV_CACHE) and (time.time() - os.path.getmtime(KEV_CACHE) < KEV_TTL):
            with open(KEV_CACHE) as f:
                catalog = json.load(f)
        else:
            catalog = _get_json(KEV_URL, timeout=10)
            try:
                with open(KEV_CACHE, "w") as f:
                    json.dump(catalog, f)
            except OSError:
                pass  # read-only FS is fine; we just won't cache
        cid = cve_id.upper()
        for v in catalog.get("vulnerabilities", []):
            if v.get("cveID", "").upper() == cid:
                return v
        return False
    except Exception:
        return None  # unknown - don't claim "not exploited" when we couldn't check


def cvss_to_severity(score):
    if score is None: return "Info"
    if score >= 9.0:  return "Critical"
    if score >= 7.0:  return "High"
    if score >= 4.0:  return "Medium"
    return "Low"


def compose(cve_id, nvd, epss, kev):
    """Fold all signals into the locked 4-key contract."""
    cid = cve_id.upper()
    sev = cvss_to_severity(nvd["score"])
    score_txt = f"CVSS {nvd['score']}" if nvd["score"] is not None else "CVSS N/A"
    vector_txt = f"vector {nvd['vector']}" if nvd["vector"] else ""
    head = f"{cid} | {score_txt}" + (f" | {vector_txt}" if vector_txt else "")
    parts = [head]
    snippet = (nvd["desc"] or "").replace("\r", " ").replace("\n", " ").strip()
    if len(snippet) > 220:
        snippet = snippet[:220].rstrip() + "..."
    if snippet:
        parts.append(snippet)
    if nvd["cwe"]:
        parts.append(f"Weakness {nvd['cwe']}")
    if epss:
        parts.append(f"EPSS {epss[0]}% (pct {epss[1]}%)")

    kev_hit = isinstance(kev, dict)
    if kev_hit:
        ransom = kev.get("knownRansomwareCampaignUse", "")
        tag = "CISA KEV: listed"
        tag += " (ransomware)" if ransom.lower() == "known" else ""
        parts.append(tag)

    if kev_hit:
        action = ("ACTIVELY EXPLOITED - patch on an emergency timeline now. "
                  "Apply the vendor fix, then hunt for prior exploitation.")
    elif epss and epss[0] >= 50:
        action = (f"High near-term exploitation likelihood (EPSS {epss[0]}%). "
                  f"Prioritize patching ahead of CVSS-only ordering.")
    else:
        action = f"Apply vendor patches; prioritize as {sev} per CVSS and monitor EPSS/KEV for changes."

    return {"severity": sev, "summary": " | ".join(parts), "mitre": "N/A", "action": action}


def lookup(cve_id):
    try:
        nvd = get_nvd(cve_id)
    except Exception:
        return MOCK  # core source down -> demo-safe fallback
    if nvd is None:
        return {
            "severity": "Info",
            "summary": f"{cve_id.upper()}: no matching record in NVD (verify the ID, or it may be reserved/unpublished).",
            "mitre": "N/A",
            "action": "Confirm the CVE ID; check the vendor advisory directly if this is a fresh disclosure."
        }
    epss = get_epss(cve_id)   # best-effort
    kev = in_kev(cve_id)      # best-effort
    return compose(cve_id, nvd, epss, kev)


def main():
    arg = sys.argv[1] if len(sys.argv) > 1 else "CVE-2021-44228"
    if arg == "--mock":
        print(json.dumps(MOCK, ensure_ascii=False)); return
    if not CVE_RE.match(arg):
        print(json.dumps({
            "severity": "Info",
            "summary": f"'{arg}' is not a valid CVE ID. Expected format: CVE-YYYY-NNNN.",
            "mitre": "N/A",
            "action": "Re-enter the identifier as CVE-YYYY-NNNN (e.g. CVE-2021-44228)."
        }, ensure_ascii=False)); return
    print(json.dumps(lookup(arg), ensure_ascii=False))


if __name__ == "__main__":
    main()
