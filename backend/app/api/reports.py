"""Stored report browsing (Module 4) and on-chain integrity registry (Module 6)."""

from fastapi import APIRouter, HTTPException, Query
from starlette.concurrency import run_in_threadpool

from app.services.reports_store import get_raw_report, get_report, list_reports
from app.services.web3_registry import (
    RegistryUnavailable,
    register_hash,
    report_hash,
    verify_hash,
)

router = APIRouter()


@router.get("/reports")
async def reports(limit: int = Query(50, ge=1, le=50)):
    """Stored reports, newest first, limit 50."""
    return list_reports(limit=limit)


@router.get("/reports/{report_id}")
async def report_detail(report_id: str):
    report = get_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


def _verdict_of(report: dict) -> str:
    """The stored risk class, which is the only thing put on-chain besides the hash."""
    verdict = report.get("risk_class")
    if not verdict:
        verdict = (report.get("risk_report") or {}).get("category")
    return str(verdict or "Unknown")


@router.post("/reports/{report_id}/register")
async def register(report_id: str):
    """
    Registers the SHA-256 hash of the stored report (plus its risk class) on the
    local ThreatRegistry. Raw report content never leaves the database.
    """
    report = get_raw_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")

    hex_hash = report_hash(report)

    try:
        return await run_in_threadpool(register_hash, hex_hash, _verdict_of(report))
    except RegistryUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@router.get("/reports/{report_id}/verify")
async def verify(report_id: str):
    """
    Recomputes the report's hash and asks the registry whether it is anchored.
    A hash that was never registered returns exists=false - nothing is faked.
    """
    report = get_raw_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")

    hex_hash = report_hash(report)

    try:
        return await run_in_threadpool(verify_hash, hex_hash)
    except RegistryUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))
