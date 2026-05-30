import json
import os
import pathlib
import sys


GREYNOISE_MOCK = {
    "185.220.101.34":  {"classification": "malicious", "tags": ["Tor exit node", "C2", "scanner"]},
    "203.0.113.45":    {"classification": "malicious", "tags": ["phishing", "credential harvesting"]},
    "198.51.100.77":   {"classification": "malicious", "tags": ["brute force", "RDP scanner"]},
    "45.33.32.156":    {"classification": "malicious", "tags": ["ransomware", "C2", "Tor"]},
    "10.99.88.77":     {"classification": "malicious", "tags": ["C2", "DNS tunnel"]},
    "10.0.0.50":       {"classification": "benign", "tags": ["internal", "corporate"]},
}

PASSIVE_DNS_MOCK = {
    "c2-malware.example.com":        {"resolutions": [{"ip": "185.220.101.34", "first_seen": "2026-05-01", "last_seen": "2026-05-30"}], "registrar": "NICENIC", "created": "2026-04-15"},
    "phish-login.example.com":       {"resolutions": [{"ip": "203.0.113.45", "first_seen": "2026-05-28", "last_seen": "2026-05-30"}], "registrar": "Namecheap", "created": "2026-05-27"},
    "secure-login-update.com":       {"resolutions": [{"ip": "203.0.113.45", "first_seen": "2026-05-28", "last_seen": "2026-05-30"}], "registrar": "Namecheap", "created": "2026-05-27"},
    "payload.example.com":           {"resolutions": [{"ip": "10.99.88.77", "first_seen": "2026-05-29", "last_seen": "2026-05-30"}], "registrar": "Porkbun", "created": "2026-05-28"},
    "c2-beacon.evil-hackers.com":    {"resolutions": [{"ip": "10.99.88.77", "first_seen": "2026-05-20", "last_seen": "2026-05-30"}], "registrar": "NICENIC", "created": "2026-05-18"},
    "ransom-c2.tor-exit.example":    {"resolutions": [{"ip": "45.33.32.156", "first_seen": "2026-05-25", "last_seen": "2026-05-30"}], "registrar": "ALIBABA", "created": "2026-05-22"},
    "backup-repo.internal.corp.com": {"resolutions": [{"ip": "10.0.0.50", "first_seen": "2024-01-01", "last_seen": "2026-05-30"}], "registrar": "internal", "created": "2023-06-01"},
    "github.com":                    {"resolutions": [{"ip": "140.82.121.3", "first_seen": "2010-01-01", "last_seen": "2026-05-30"}], "registrar": "MarkMonitor", "created": "2007-10-01"},
    "npmjs.org":                     {"resolutions": [{"ip": "104.16.22.35", "first_seen": "2010-01-01", "last_seen": "2026-05-30"}], "registrar": "MarkMonitor", "created": "2009-01-01"},
}


def _skill_dir() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parents[1]


def mock_greynoise(ip):
    return GREYNOISE_MOCK.get(ip, {"classification": "unknown", "tags": []})


def mock_passive_dns(domain):
    return PASSIVE_DNS_MOCK.get(domain, None)


def _enrich_iocs(iocs):
    enriched = {"ip": [], "domain": [], "url": [], "sha256": [], "md5": [], "sha1": []}
    threat_context = []
    for ip in iocs.get("ip", []):
        gn = mock_greynoise(ip)
        enriched["ip"].append({"value": ip, "greynoise": gn})
        if gn["classification"] == "malicious":
            threat_context.append(f"IP {ip} classified as malicious (GreyNoise: {', '.join(gn['tags'])})")
        elif gn["classification"] == "benign":
            threat_context.append(f"IP {ip} classified as benign (GreyNoise)")
    for domain in iocs.get("domain", []):
        pdns = mock_passive_dns(domain)
        enriched["domain"].append({"value": domain, "passive_dns": pdns})
        if pdns:
            recent = pdns.get("resolutions", [])
            if recent:
                threat_context.append(f"Domain {domain} resolved to {recent[-1]['ip']} (registrar: {pdns.get('registrar', 'unknown')}, created: {pdns.get('created', 'unknown')})")
    for url in iocs.get("url", []):
        enriched["url"].append({"value": url})
    for sha in iocs.get("sha256", []):
        enriched["sha256"].append({"value": sha})
    for md5 in iocs.get("md5", []):
        enriched["md5"].append({"value": md5})
    for sha1 in iocs.get("sha1", []):
        enriched["sha1"].append({"value": sha1})
    return enriched, "; ".join(threat_context) if threat_context else "no threat intel hits"


def enrich(alert):
    iocs = alert.get("iocs", {})
    enriched_iocs, threat_context = _enrich_iocs(iocs)
    result = {
        "alert_id": alert.get("id", "unknown"),
        "alert_type": alert.get("type", "unknown"),
        "raw_text": alert.get("raw_text", ""),
        "severity": alert.get("severity", "Info"),
        "source": alert.get("source", "unknown"),
        "keywords": alert.get("keywords", []),
        "enriched_iocs": enriched_iocs,
        "threat_context": threat_context,
    }
    return result


def main():
    if len(sys.argv) > 1:
        path = pathlib.Path(sys.argv[1])
        if path.exists():
            with open(path, encoding="utf-8") as f:
                alert = json.load(f)
            result = enrich(alert)
            print(json.dumps(result, ensure_ascii=False))
            return
    print(json.dumps({"error": "usage: python enrich.py <alert.json>"}, ensure_ascii=False))


if __name__ == "__main__":
    main()
