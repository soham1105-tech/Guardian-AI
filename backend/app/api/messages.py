"""Pasted-message analysis + report persistence (Module 4 dependency)."""

import uuid

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, field_validator

from app.services.message_analyzer import analyze_message
from app.services.reports_store import (
    build_indicators,
    campaign_summary,
    find_related,
    record_report,
)

router = APIRouter()


class MessageRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=20000, description="Pasted message / SMS text")

    @field_validator("text")
    @classmethod
    def _not_blank(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("text must not be empty")
        return value


@router.post("/analyze-message")
async def analyze_message_endpoint(payload: MessageRequest):
    """
    Analyses a pasted message with the deterministic pipeline and stores it as
    a report, linking it to earlier reports that share an exact indicator.
    """
    try:
        report = await analyze_message(payload.text)
    except Exception as exc:  # never 500 on a user-supplied message
        raise HTTPException(status_code=500, detail=f"Message analysis failed: {type(exc).__name__}")

    report_id = str(uuid.uuid4())
    report["email_id"] = report_id
    report["id"] = report_id

    indicators = build_indicators(
        domain=report.get("domain"),
        brand=report.get("brand"),
        contacts=report.get("contacts"),
    )
    related = find_related(
        indicators, exclude_id=report_id, new_risk_class=report.get("risk_class")
    )
    report["related_reports"] = related
    summary = campaign_summary(related)
    if summary:
        report["campaign_summary"] = summary

    record_report(
        report_id=report_id,
        input_type="message",
        input_text=payload.text,
        final_url=report.get("final_url"),
        domain=report.get("domain"),
        brand=report.get("brand"),
        risk_class=report.get("risk_class"),
        risk_score=report.get("risk_score"),
        indicators=indicators,
        evidence=report.get("evidence"),
        report=report,
    )

    return report
