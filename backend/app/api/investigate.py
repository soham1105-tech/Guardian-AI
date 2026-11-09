import json
import uuid

from fastapi import APIRouter, HTTPException

from app.database import get_db
from app.models.schemas import InvestigateRequest
from app.services.link_investigator import investigate_link
from app.services.reports_store import (
    build_indicators,
    campaign_summary,
    final_registered_domain,
    find_related,
    record_report,
)
from app.services.ssrf_guard import SSRFBlockedError
from app.services.url_normalizer import InvalidURLError

router = APIRouter()


@router.post("/investigate")
async def investigate(payload: InvestigateRequest):
    """
    Investigates a single user-supplied URL or domain with the same pipeline
    stages (heuristics, threat intel, risk engine, AI verdict) the email flow
    uses — and returns the same report shape.

    The result is stored twice: under a fresh id in the legacy emails/analyses
    tables (so the dashboard list keeps working unchanged) and in the reports
    table, where earlier reports sharing an exact indicator are linked back.
    """
    try:
        result = await investigate_link(payload.url)
    except InvalidURLError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid URL: {exc}")
    except SSRFBlockedError as exc:
        # Rejected before any network request was attempted.
        raise HTTPException(
            status_code=400,
            detail=f"Blocked by SSRF guard: {exc}",
        )

    investigation_id = str(uuid.uuid4())
    display = result["checks"]["display_url"]
    result["email_id"] = investigation_id
    result["id"] = investigation_id
    result["checks"]["investigation_id"] = investigation_id

    checks = result.get("checks") or {}
    final_url = (checks.get("redirects") or {}).get("final_url")
    # Correlate on the domain the user actually lands on, not the submitted one.
    domain = final_registered_domain(final_url, checks.get("registered_domain"))
    brand = (checks.get("domain_intel") or {}).get("brand")

    # --- deterministic campaign correlation (exact indicator matches only) ---
    indicators = build_indicators(domain=domain, brand=brand)
    related = find_related(
        indicators, exclude_id=investigation_id, new_risk_class=result.get("risk_class")
    )
    result["related_reports"] = related
    summary = campaign_summary(related)
    if summary:
        result["campaign_summary"] = summary

    with get_db() as conn:
        conn.execute(
            "INSERT INTO emails (id, filename, filepath, status) VALUES (?, ?, ?, ?)",
            (investigation_id, display[:255], f"link://{checks.get('normalized_url')}", "completed"),
        )
        conn.execute(
            "INSERT INTO analyses (id, email_id, risk_score, risk_category, result_json) VALUES (?, ?, ?, ?, ?)",
            (
                investigation_id,
                investigation_id,
                result["risk_report"]["score"],
                result["risk_report"]["category"],
                json.dumps(result),
            ),
        )
        conn.commit()

    record_report(
        report_id=investigation_id,
        input_type="url",
        input_text=payload.url,
        final_url=final_url,
        domain=domain,
        brand=brand,
        risk_class=result.get("risk_class"),
        risk_score=result.get("risk_score"),
        indicators=indicators,
        evidence=result.get("evidence"),
        report=result,
    )

    return result
