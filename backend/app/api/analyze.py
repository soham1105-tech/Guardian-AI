import json
from fastapi import APIRouter, HTTPException

from app.database import get_db
from app.services.email_parser import parse_email
from app.services.header_analyzer import analyze_headers
from app.services.url_analyzer import analyze_urls
from app.services.domain_intel import check_domain
from app.services.url_normalizer import normalize_url
from app.services.attachment_analyzer import analyze_attachments
from app.services.ioc_extractor import extract_iocs
from app.services.risk_engine import calculate_risk
from app.services.ai_analyzer import get_ai_verdict
from app.services.mitre_mapper import map_techniques
from app.services.threat_intel.provider_manager import check_iocs_batch, summarize_threat_intel
from app.services.link_investigator import risk_class_for
from app.services.reports_store import (
    build_indicators,
    campaign_summary,
    find_related,
    get_report,
    record_report,
)
from app.config import settings

router = APIRouter()


@router.post("/analyze/{email_id}")
async def analyze_email(email_id: str):
    # --- 1. Fetch email record ---
    with get_db() as conn:
        row = conn.execute("SELECT * FROM emails WHERE id = ?", (email_id,)).fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="Email not found")

    filepath = row["filepath"]

    # --- 2. Run static analysis pipeline stage by stage ---
    parsed = parse_email(filepath)
    header_result = analyze_headers(parsed)
    url_results = analyze_urls(parsed["urls"])
    attachment_results = analyze_attachments(parsed["attachments"])
    ioc_summary = extract_iocs(parsed, url_results, attachment_results)

    # --- 3. Threat Intelligence lookups (V2) — live, external verification ---
    threat_intel_results = await check_iocs_batch(
        ioc_summary, max_per_type=settings.MAX_IOC_CHECK_PER_TYPE
    )
    threat_intel_summary = summarize_threat_intel(threat_intel_results)

    # --- 4. Risk scoring (now includes the threat-intel signal) ---
    risk_report = calculate_risk(
        header_analysis=header_result,
        url_analysis=url_results,
        attachment_analysis=attachment_results,
        body_text=parsed.get("body_text", ""),
        threat_intel_summary=threat_intel_summary,
    )

    # --- 5. MITRE ATT&CK technique mapping (V2) ---
    mitre_techniques = map_techniques(header_result, url_results, attachment_results)

    # --- 6. AI verdict (structured evidence only, not raw email) ---
    evidence = {
        "sender_domain": header_result["sender_domain"],
        "spf": header_result["spf"],
        "dkim": header_result["dkim"],
        "dmarc": header_result["dmarc"],
        "domain_mismatch": header_result["domain_mismatch"],
        "url_count": len(url_results),
        "high_risk_urls": [u["url"] for u in url_results if u["risk"] == "HIGH"],
        "attachment_count": len(attachment_results),
        "high_risk_attachments": [a["filename"] for a in attachment_results if a["risk"] == "HIGH"],
        "ioc_count": sum(len(v) for v in ioc_summary.values()),
        "threat_intel_malicious_count": threat_intel_summary["malicious_ioc_count"],
        "threat_intel_malicious_iocs": threat_intel_summary["malicious_iocs"],
        "mitre_techniques": [t["id"] for t in mitre_techniques],
        "risk_score": risk_report["score"],
        "risk_category": risk_report["category"],
    }
    ai_verdict = get_ai_verdict(evidence)

    # --- 7. Remove raw_bytes before returning/saving ---
    for att in parsed.get("attachments", []):
        att.pop("raw_bytes", None)

    result = {
        "email_id": email_id,
        "parsed": {
            "from_addr": parsed["from_addr"],
            "to_addr": parsed["to_addr"],
            "subject": parsed["subject"],
            "date": parsed["date"],
            "urls": parsed["urls"],
            "attachments": parsed["attachments"],
        },
        "header_analysis": header_result,
        "url_analysis": url_results,
        "attachment_analysis": attachment_results,
        "ioc_summary": ioc_summary,
        "threat_intel": {
            "results": threat_intel_results,
            "summary": threat_intel_summary,
        },
        "mitre_techniques": mitre_techniques,
        "risk_report": risk_report,
        "ai_verdict": ai_verdict,
    }

    # --- 7b. Deterministic campaign correlation (exact matches only) ---
    # An email links through its sender domain, and through an impersonated
    # brand when a URL in the body targets one.
    brand = None
    for item in url_results[:3]:
        candidate = item.get("domain")
        if not candidate:
            continue
        try:
            brand = check_domain(normalize_url(f"https://{candidate}")).get("brand")
        except Exception:
            brand = None
        if brand:
            break

    indicators = build_indicators(
        brand=brand, sender_domain=header_result.get("sender_domain")
    )
    email_risk_class = risk_class_for(
        risk_report["score"],
        has_threat_intel=threat_intel_summary["malicious_ioc_count"] > 0,
    )
    related = find_related(
        indicators, exclude_id=email_id, new_risk_class=email_risk_class
    )
    result["related_reports"] = related
    summary = campaign_summary(related)
    if summary:
        result["campaign_summary"] = summary

    # --- 8. Save to DB ---
    with get_db() as conn:
        conn.execute(
            "INSERT INTO analyses (id, email_id, risk_score, risk_category, result_json) VALUES (?, ?, ?, ?, ?)",
            (email_id, email_id, risk_report["score"], risk_report["category"], json.dumps(result)),
        )
        conn.execute("UPDATE emails SET status = ? WHERE id = ?", ("completed", email_id))
        conn.commit()

    record_report(
        report_id=email_id,
        input_type="email",
        input_text=row["filename"],
        final_url=None,
        domain=None,
        brand=brand,
        risk_class=email_risk_class,
        risk_score=round(risk_report["score"] / 10, 1),
        indicators=indicators,
        evidence=[],
        report=result,
    )

    return result


@router.get("/analyses")
async def list_analyses():
    with get_db() as conn:
        rows = conn.execute(
            """SELECT a.id, a.email_id, e.filename, a.risk_score, a.risk_category, a.created_at
               FROM analyses a JOIN emails e ON a.email_id = e.id
               ORDER BY a.created_at DESC"""
        ).fetchall()
    return [dict(row) for row in rows]


@router.get("/analyses/{email_id}")
async def get_analysis(email_id: str):
    with get_db() as conn:
        row = conn.execute("SELECT result_json FROM analyses WHERE email_id = ?", (email_id,)).fetchone()
    if row is not None:
        return json.loads(row["result_json"])

    # Message reports are only stored in the reports table; serve them through
    # the same URL so the existing report view can open them unchanged.
    stored = get_report(email_id)
    if stored is not None:
        return stored

    raise HTTPException(status_code=404, detail="Analysis not found")