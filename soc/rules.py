from typing import Dict


def get_severity(predicted_label: str, confidence: float) -> str:
    """
    Convert model output into SOC severity level.
    """
    if predicted_label == "BENIGN":
        return "INFO"

    if predicted_label == "DDoS":
        if confidence < 0.70:
            return "MEDIUM"
        elif confidence < 0.90:
            return "HIGH"
        else:
            return "CRITICAL"

    return "UNKNOWN"


def get_recommended_action(predicted_label: str, confidence: float) -> str:
    """
    Convert model output into recommended SOC action.
    """
    if predicted_label == "BENIGN":
        return "No action"

    if predicted_label == "DDoS":
        if confidence < 0.70:
            return "Monitor source IP"
        elif confidence < 0.90:
            return "Investigate and rate-limit source IP"
        else:
            return "Recommend firewall block for source IP"

    return "Escalate for manual review"


def build_alert_record(
    timestamp: str,
    attacker_ip: str,
    target_ip: str,
    target_port: int,
    predicted_label: str,
    confidence: float,
    ddos_probability: float
) -> Dict:
    """
    Build a complete SOC alert record from inference output + traffic metadata.
    """
    severity = get_severity(predicted_label, confidence)
    recommended_action = get_recommended_action(predicted_label, confidence)

    return {
        "timestamp": timestamp,
        "attacker_ip": attacker_ip,
        "target_ip": target_ip,
        "target_port": target_port,
        "predicted_label": predicted_label,
        "confidence": round(confidence, 4),
        "ddos_probability": round(ddos_probability, 4),
        "severity": severity,
        "recommended_action": recommended_action
    }


if __name__ == "__main__":
    # Quick local tests
    sample_1 = build_alert_record(
        timestamp="2026-03-23 20:45:00",
        attacker_ip="192.168.1.55",
        target_ip="10.0.0.12",
        target_port=80,
        predicted_label="BENIGN",
        confidence=0.9998,
        ddos_probability=0.0002
    )

    sample_2 = build_alert_record(
        timestamp="2026-03-23 20:46:00",
        attacker_ip="192.168.1.101",
        target_ip="10.0.0.20",
        target_port=443,
        predicted_label="DDoS",
        confidence=0.965,
        ddos_probability=0.965
    )

    print("Sample BENIGN alert:")
    print(sample_1)
    print("\nSample DDoS alert:")
    print(sample_2)