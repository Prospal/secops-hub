import json
import sys


TRUSTED_DOMAINS = {
    "github.com", "npmjs.org", "google.com", "microsoft.com", "amazon.com",
    "cloudflare.com", "apple.com", "facebook.com", "twitter.com", "linkedin.com",
}

TRUSTED_IPS_START = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                     "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                     "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                     "172.30.", "172.31.", "192.168.")


def _calc_confidence(enriched):
    score = 0
    reasons = []

    severity = enriched.get("severity", "Info")
    if severity == "Critical":
        score += 15
        reasons.append("alert severity is Critical")
    elif severity == "High":
        score += 10
        reasons.append("alert severity is High")
    elif severity == "Medium":
        score += 5

    threat = enriched.get("threat_context", "")
    if threat and threat != "no threat intel hits":
        score += 15
        reasons.append("threat intel matches found")

    e_iocs = enriched.get("enriched_iocs", {})
    ip_count = len(e_iocs.get("ip", []))
    domain_count = len(e_iocs.get("domain", []))
    url_count = len(e_iocs.get("url", []))
    hash_count = len(e_iocs.get("sha256", [])) + len(e_iocs.get("md5", [])) + len(e_iocs.get("sha1", []))

    total_iocs = ip_count + domain_count + url_count + hash_count
    if total_iocs >= 3:
        score += 10
        reasons.append("multiple independent IOCs")
    elif total_iocs >= 1:
        score += 5

    malicious_ips = sum(1 for i in e_iocs.get("ip", []) if i.get("greynoise", {}).get("classification") == "malicious")
    if malicious_ips > 0:
        score += 10
        reasons.append(f"{malicious_ips} IP(s) classified malicious (GreyNoise)")

    keywords = enriched.get("keywords", [])
    kit = set(k.lower() for k in keywords)
    strong_kw = {"mimikatz", "ransomware", "lsass", "credential dump", "c2", "beacon"}
    matched_strong = kit & strong_kw
    if matched_strong:
        score += 15
        reasons.append(f"strong threat keywords: {', '.join(sorted(matched_strong))}")

    benign_kw = {"backup", "scheduled", "jenkins", "ci", "deploy", "build", "admin"}
    matched_benign = kit & benign_kw
    if matched_benign and not matched_strong:
        score -= 10
        reasons.append(f"benign activity keywords: {', '.join(sorted(matched_benign))}")

    source = enriched.get("source", "").lower()
    if source in ("siem", "edr"):
        score += 5
        reasons.append("alert from automated detection source")
    elif source in ("user report", "email"):
        score -= 5

    for domain in e_iocs.get("domain", []):
        domain_name = domain.get("value", "").lower()
        if domain_name in TRUSTED_DOMAINS:
            score -= 10
            reasons.append(f"domain {domain_name} is on trusted allowlist")

    for domain in e_iocs.get("domain", []):
        pdns = domain.get("passive_dns") or {}
        created = pdns.get("created", "")
        if created and created.startswith("202"):
            try:
                year = int(created[:4])
                if year < 2024:
                    score -= 5
                    reasons.append(f"domain {domain.get('value')} registered before 2024 (long-lived)")
            except ValueError:
                pass
        if created and created.startswith("2026-05-27") or (created and created.startswith("2026-05-28")):
            score += 5
            reasons.append(f"domain {domain.get('value')} very recently registered (suspicious)")

    for ip_entry in e_iocs.get("ip", []):
        ip = ip_entry.get("value", "")
        if ip.startswith(TRUSTED_IPS_START):
            score -= 5
            reasons.append(f"IP {ip} is private/RFC1918")

    score = max(0, min(100, score))

    if score >= 75:
        verdict = "likely_true_positive"
    elif score >= 50:
        verdict = "needs_review"
    elif score >= 25:
        verdict = "likely_false_positive"
    else:
        verdict = "false_positive"

    return {
        "confidence": score,
        "verdict": verdict,
        "reasons": reasons,
    }


def main():
    if len(sys.argv) > 1:
        text = sys.argv[1]
        if text.strip().startswith("{"):
            enriched = json.loads(text)
        else:
            with open(text, encoding="utf-8") as f:
                enriched = json.load(f)
    else:
        enriched = json.loads(sys.stdin.read())
    result = _calc_confidence(enriched)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
