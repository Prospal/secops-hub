import json
import sys


def _decide(alert, enriched, classification):
    severity = alert.get("severity", "Info")
    confidence = classification.get("confidence", 0)
    alert_type = alert.get("type", "unknown")

    if severity == "Critical" and confidence >= 60:
        decision = "escalate"
        reason = f"Critical severity ({severity}) with confidence {confidence}% — auto-escalating"
    elif severity == "High" and confidence >= 70:
        decision = "escalate"
        reason = f"High severity ({severity}) with high confidence {confidence}% — auto-escalating"
    elif confidence >= 80:
        decision = "escalate"
        reason = f"Confidence {confidence}% — auto-escalating"
    elif confidence >= 50:
        decision = "review"
        reason = f"Confidence {confidence}% — review recommended by Tier-2 analyst"
    else:
        decision = "suppress"
        reason = f"Low confidence {confidence}% — suppress (journal only)"

    return {
        "decision": decision,
        "reason": reason,
        "needs_human": decision in ("escalate", "review"),
        "confidence": confidence,
    }


def main():
    if len(sys.argv) > 1:
        data = sys.argv[1]
        if data.strip().startswith("{"):
            payload = json.loads(data)
        else:
            with open(data, encoding="utf-8") as f:
                payload = json.load(f)
    else:
        payload = json.loads(sys.stdin.read())

    alert = payload.get("alert", {})
    enriched = payload.get("enriched", {})
    classification = payload.get("classification", {})

    result = _decide(alert, enriched, classification)
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
