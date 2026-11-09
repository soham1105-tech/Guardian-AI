from app.config import settings


def calculate_risk(
    header_analysis: dict,
    url_analysis: list,
    attachment_analysis: list,
    body_text: str = "",
    threat_intel_summary: dict = None,
) -> dict:
    """
    Combines all analysis stages — including live threat-intelligence
    results (V2) — into one final risk score (0-100) using documented,
    deterministic weights.
    """
    threat_intel_summary = threat_intel_summary or {}

    sender_score = _score_sender(header_analysis)
    url_score = _score_urls(url_analysis)
    attachment_score = _score_attachments(attachment_analysis)
    content_score = _score_content(body_text)
    threat_intel_score = _score_threat_intel(threat_intel_summary)

    final_score = (
        (sender_score * settings.WEIGHT_SENDER / 100) +
        (url_score * settings.WEIGHT_URL / 100) +
        (attachment_score * settings.WEIGHT_ATTACHMENT / 100) +
        (content_score * settings.WEIGHT_CONTENT / 100) +
        (threat_intel_score * settings.WEIGHT_THREAT_INTEL / 100)
    )
    final_score = round(min(final_score, 100))

    category = _categorize(final_score)

    return {
        "score": final_score,
        "category": category,
        "breakdown": {
            "sender_score": sender_score,
            "url_score": url_score,
            "attachment_score": attachment_score,
            "content_score": content_score,
            "threat_intel_score": threat_intel_score,
            "weights": {
                "sender": settings.WEIGHT_SENDER,
                "url": settings.WEIGHT_URL,
                "attachment": settings.WEIGHT_ATTACHMENT,
                "content": settings.WEIGHT_CONTENT,
                "threat_intel": settings.WEIGHT_THREAT_INTEL,
            },
        },
    }


def _score_sender(header_analysis: dict) -> int:
    risk_map = {"HIGH": 100, "MEDIUM": 55, "LOW": 10}
    return risk_map.get(header_analysis.get("spoofing_risk", "LOW"), 10)


def _score_urls(url_analysis: list) -> int:
    if not url_analysis:
        return 0
    return max((item.get("risk_score", 0) for item in url_analysis), default=0)


def _score_attachments(attachment_analysis: list) -> int:
    if not attachment_analysis:
        return 0
    return max((item.get("risk_score", 0) for item in attachment_analysis), default=0)


def _score_content(body_text: str) -> int:
    if not body_text:
        return 0

    urgency_phrases = [
        "act now", "urgent", "immediately", "verify your account",
        "suspended", "click here", "limited time", "confirm your identity",
        "unusual activity", "your account will be closed"
    ]

    body_lower = body_text.lower()
    matches = sum(1 for phrase in urgency_phrases if phrase in body_lower)

    return min(matches * 20, 100)


def _score_threat_intel(threat_intel_summary: dict) -> int:
    """
    A confirmed-malicious IOC is a binary, high-trust signal — a domain
    either has been reported as malicious or it hasn't. Using the raw
    vendor-consensus percentage alone (e.g. "1/91 vendors flagged")
    would let a genuinely malicious but under-reported IOC contribute
    almost nothing to the score.

    So: any confirmed-malicious IOC guarantees a meaningful floor score,
    while still letting high-consensus detections (e.g. 40/91 vendors)
    score higher than a single-vendor flag.
    """
    malicious_count = threat_intel_summary.get("malicious_ioc_count", 0)
    max_confidence = threat_intel_summary.get("max_confidence", 0)

    if malicious_count == 0:
        return 0

    FLOOR_ON_MALICIOUS = 60
    return max(max_confidence, FLOOR_ON_MALICIOUS)


def _categorize(score: int) -> str:
    if score >= settings.THRESHOLD_HIGH:
        return "CRITICAL"
    elif score >= settings.THRESHOLD_SUSPICIOUS:
        return "HIGH"
    elif score >= settings.THRESHOLD_SAFE:
        return "SUSPICIOUS"
    else:
        return "SAFE"