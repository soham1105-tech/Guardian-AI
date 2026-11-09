"""Deterministic analysis of a pasted message / SMS / chat transcript.

NOTE: this endpoint (``POST /api/analyze-message``) is described by the
project brief as Prompt 3 work, but it did not exist anywhere in this
checkout (no route, no service, no frontend caller). It is implemented here
because Module 4 has to correlate *message* reports and the verification steps
call the endpoint directly. It reuses the existing pipeline pieces (URL
heuristics, the link investigator, content scoring, MITRE mapping) and adds no
new verdict rules.

Everything in here is rule-based. No LLM call is made to decide anything.
"""

import re

from app.services.ai_analyzer import get_ai_verdict
from app.services.ioc_extractor import extract_iocs
from app.services.link_investigator import (
    VERDICT_BY_CATEGORY,
    _combine,
    investigate_link,
    risk_class_for,
)
from app.services.mitre_mapper import map_techniques
from app.services.reports_store import final_registered_domain
from app.services.risk_engine import _categorize, _score_content
from app.services.ssrf_guard import SSRFBlockedError
from app.services.url_analyzer import analyze_urls
from app.services.url_normalizer import InvalidURLError

# --- contacts: exact-match identifiers used by campaign correlation ---------
URL_REGEX = re.compile(r"https?://[^\s<>\"'`]+", re.IGNORECASE)

# Indian mobile numbers, optionally +91 prefixed, never part of a longer number.
PHONE_REGEX = re.compile(r"(?<![\d+])(?:\+?91[\s\-.()]*)?[6-9]\d{9}(?!\d)")

# UPI handles end in a bank/VPA handle, not a country-code TLD. Using an
# allowlist keeps "someone@example.com" from being mistaken for a UPI ID.
UPI_HANDLES = (
    "ybl", "paytm", "okaxis", "okhdfcbank", "okicici", "oksbi", "okbizaxis",
    "upi", "apl", "axisb", "ibl", "axl", "airtel", "fbl", "jupiteraxis",
    "yesg", "yesbank", "hdfcbank", "icici", "sbi", "kotak", "indus", "cnrb",
    "idfcbank", "barodampay", "freecharge", "pingpay", "slice", "waaxis",
    "superyes", "naviaxis", "timecosmos", "shriram", "abfspay", "dbs",
)
UPI_REGEX = re.compile(
    r"\b[A-Za-z0-9._-]{2,64}@(?:" + "|".join(UPI_HANDLES) + r")\b",
    re.IGNORECASE,
)

PAYMENT_LINK_HOSTS = (
    "paytm.me", "p-y.tm", "razorpay.me", "rzp.io", "instamojo.com",
    "phonepe.me", "bit.ly/upi", "gpay.app", "bhim.app", "upi.link",
)
PAYMENT_LINK_REGEX = re.compile(
    r"(?:upi://[a-z]+|https?://(?:[a-z0-9-]+\.)?(?:"
    + "|".join(re.escape(host.split("/")[0]) for host in PAYMENT_LINK_HOSTS)
    + r"))[^\s<>\"'`]*",
    re.IGNORECASE,
)

PAYMENT_CONTACT_SCORE = 45   # an unsolicited "pay here" identifier is a real signal
CONTACTS_MAX = 10


def _trim(value: str, limit: int = 200) -> str:
    return value if len(value) <= limit else value[:limit]


def extract_urls(text: str) -> list:
    seen = []
    for raw in URL_REGEX.findall(text or ""):
        url = raw.rstrip(").,;!?\"'")
        if url and url not in seen:
            seen.append(url)
    return seen


def extract_contacts(text: str) -> dict:
    text = text or ""

    # Phone numbers are written with all sorts of separators ("+91 98765 43210",
    # "98765-43210"). Collapse separators that sit between digits, then match.
    compact = re.sub(r"(?<=\d)[\s().-]+(?=\d)", "", text)

    phones = []
    for match in PHONE_REGEX.finditer(compact):
        value = match.group(0).strip()
        if value not in phones:
            phones.append(value)

    upis = []
    for match in UPI_REGEX.finditer(text):
        value = match.group(0)
        if value.lower() not in [item.lower() for item in upis]:
            upis.append(value)

    payment_links = []
    for match in PAYMENT_LINK_REGEX.finditer(text):
        value = match.group(0).rstrip(").,;!?\"'")
        if value and value.lower() not in [item.lower() for item in payment_links]:
            payment_links.append(value)

    return {
        "phones": phones[:CONTACTS_MAX],
        "upi_ids": upis[:CONTACTS_MAX],
        "payment_links": payment_links[:CONTACTS_MAX],
    }


def has_payment_contact(contacts: dict) -> bool:
    return bool(
        contacts.get("phones") or contacts.get("upi_ids") or contacts.get("payment_links")
    )


async def analyze_message(text: str) -> dict:
    """
    Builds a report with the same shape the dashboard already renders
    (parsed / header_analysis / url_analysis / ioc_summary / threat_intel /
    mitre_techniques / risk_report / ai_verdict) plus message-specific fields.
    """
    text = (text or "").strip()
    urls = extract_urls(text)
    contacts = extract_contacts(text)

    link_report = None
    if urls:
        try:
            link_report = await investigate_link(urls[0])
        except (InvalidURLError, SSRFBlockedError):
            link_report = None

    if link_report:
        url_analysis = link_report["url_analysis"]
        ioc_summary = link_report["ioc_summary"]
        threat_intel = link_report["threat_intel"]
        final_url = link_report["checks"]["redirects"]["final_url"]
        domain = final_registered_domain(
            final_url, link_report["checks"]["registered_domain"]
        )
        brand = (link_report["checks"]["domain_intel"] or {}).get("brand")
        link_score = link_report["risk_report"]["score"]
    else:
        url_analysis = analyze_urls(urls[:3])
        ioc_summary = extract_iocs({"from_addr": None, "body_text": text, "received_headers": []},
                                   url_analysis, [])
        threat_intel = {
            "results": {},
            "summary": {"total_iocs_checked": 0, "malicious_ioc_count": 0,
                        "malicious_iocs": [], "max_confidence": 0},
        }
        final_url = urls[0] if urls else None
        domain = final_registered_domain(
            final_url, url_analysis[0]["domain"] if url_analysis else None
        )
        brand = None
        link_score = max((item.get("risk_score", 0) for item in url_analysis), default=0)

    content_score = _score_content(text)
    contact_score = PAYMENT_CONTACT_SCORE if has_payment_contact(contacts) else 0

    components = {
        "link_score": link_score,
        "content_score": content_score,
        "payment_contact_score": contact_score,
    }
    score = min(100, _combine(components))
    category = _categorize(score)
    has_threat_intel = threat_intel["summary"]["malicious_ioc_count"] > 0
    risk_class = risk_class_for(score, has_threat_intel=has_threat_intel)

    # --- evidence trail (deterministic) --------------------------------------
    evidence = [
        {
            "source": "Message text",
            "finding": f"{len(text)} character(s) of pasted text analysed",
            "severity": "info",
            "detail": "",
        }
    ]
    if urls:
        evidence.append({
            "source": "URL extraction",
            "finding": f"{len(urls)} link(s) found: " + ", ".join(_trim(u, 120) for u in urls[:3]),
            "severity": "info",
            "detail": "",
        })
    if contacts["phones"]:
        evidence.append({"source": "Contact extraction",
                         "finding": "Phone number(s): " + ", ".join(contacts["phones"][:3]),
                         "severity": "medium", "detail": "Requests payment or callback by phone."})
    if contacts["upi_ids"]:
        evidence.append({"source": "Contact extraction",
                         "finding": "UPI ID(s): " + ", ".join(contacts["upi_ids"][:3]),
                         "severity": "high", "detail": "Transfer request to a UPI handle."})
    if contacts["payment_links"]:
        evidence.append({"source": "Contact extraction",
                         "finding": "Payment link(s): " + ", ".join(contacts["payment_links"][:3]),
                         "severity": "high", "detail": "Direct payment link in message text."})
    if content_score:
        evidence.append({"source": "Message heuristics",
                         "finding": f"Urgency / credential phrasing scored {content_score}/100",
                         "severity": "medium", "detail": ""})
    if link_report:
        evidence.extend(link_report.get("evidence") or [])

    indicators = list(link_report.get("indicators") or []) if link_report else []
    for upi in contacts["upi_ids"]:
        indicators.append({"type": "upi", "value": upi, "severity": "high",
                           "detail": "UPI handle requested in message text"})
    for phone in contacts["phones"]:
        indicators.append({"type": "phone", "value": phone, "severity": "medium",
                           "detail": "Phone number present in message text"})

    header_analysis = {
        "spf": "N/A",
        "dkim": "N/A",
        "dmarc": "N/A",
        "sender_domain": None,
        "return_path_domain": None,
        "domain_mismatch": False,
        "spoofing_risk": "LOW",
        "reasons": ["Pasted message - email authentication (SPF/DKIM/DMARC) does not apply."],
    }

    parsed = {
        "from_addr": None,
        "to_addr": None,
        "subject": "Pasted message analysis",
        "date": None,
        "return_path": None,
        "reply_to": None,
        "received_headers": [],
        "body_text": text,
        "urls": urls,
        "attachments": [],
        "investigation_type": "message",
    }

    mitre = map_techniques(header_analysis, url_analysis, [])

    recommendations = list(link_report.get("recommendations") or []) if link_report else []
    if has_payment_contact(contacts):
        recommendations.insert(
            0,
            "Do not call the number or send money to the UPI ID / payment link in this message.",
        )
    if not recommendations:
        recommendations = ["Treat unsolicited messages with links or payment requests as untrusted."]

    summary_line = (
        f"{VERDICT_BY_CATEGORY.get(category, category)} ({score}/100) - {len(urls)} link(s), "
        f"{'payment details present' if has_payment_contact(contacts) else 'no payment details'}"
    )

    # The AI only narrates the deterministic findings above.
    ai_verdict = get_ai_verdict(
        {
            "investigation_type": "pasted_message",
            "link_count": len(urls),
            "links": urls[:3],
            "domain": domain,
            "impersonated_brand": brand,
            "phone_count": len(contacts["phones"]),
            "upi_ids": contacts["upi_ids"][:3],
            "payment_links": contacts["payment_links"][:3],
            "urgency_score": content_score,
            "threat_intel_malicious_count": threat_intel["summary"]["malicious_ioc_count"],
            "risk_score": score,
            "risk_category": category,
        }
    )

    return {
        "investigation_type": "message",
        "input_type": "message",
        "message_text": text,
        "contacts": contacts,
        "verdict": VERDICT_BY_CATEGORY.get(category, category),
        "risk_class": risk_class,
        "risk_score": round(score / 10, 1),
        "summary": summary_line,
        "indicators": indicators,
        "evidence": evidence,
        "recommendations": recommendations,
        "final_url": final_url,
        "domain": domain,
        "brand": brand,
        "parsed": parsed,
        "header_analysis": header_analysis,
        "url_analysis": url_analysis,
        "attachment_analysis": [],
        "ioc_summary": ioc_summary,
        "threat_intel": threat_intel,
        "mitre_techniques": mitre,
        "risk_report": {"score": score, "category": category, "breakdown": components},
        "ai_verdict": ai_verdict,
    }
