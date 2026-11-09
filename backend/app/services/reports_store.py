"""Deterministic report storage and campaign correlation (Module 4).

Every investigation (url / message / email) is stored as a row in the
``reports`` table with its full JSON report, plus a small list of exact
match indicators. Correlation only ever compares those indicators for
equality - there is no fuzzy matching, no similarity score, and the LLM is
never consulted to decide whether two reports belong together.
"""

import json
import re
from datetime import datetime, timezone

from app.database import get_db

INPUT_TYPES = ("url", "message", "email")

# Human wording for each indicator kind, used in the "shared indicator" line.
INDICATOR_LABELS = {
    "domain": "shared redirect domain",
    "brand": "shared impersonated brand",
    "phone": "shared phone number",
    "upi": "shared UPI ID",
    "payment": "shared payment link",
    "sender_domain": "shared sender domain",
}

# When a pair shares more than one indicator, the most meaningful one is
# reported first.
INDICATOR_PRIORITY = ["domain", "brand", "phone", "upi", "payment", "sender_domain"]

_PHONE_SEPARATORS = re.compile(r"[\s()\-.]")

# Two clean reports sharing a domain (e.g. two lookups of google.com) are not a
# fraud campaign. Correlation still links anything suspicious to anything it
# shares an exact indicator with - it just does not manufacture campaigns out
# of reports that both came back clean.
CLEAN_RISK_CLASSES = {"Low Risk", "SAFE"}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def final_registered_domain(final_url, fallback=None):
    """
    Registered domain of the URL the investigation actually ended on - the
    "final redirect domain" the correlation rule compares.
    """
    if final_url:
        try:
            from app.services.url_normalizer import normalize_url

            return normalize_url(final_url)["registered_domain"] or fallback
        except Exception:
            return fallback
    return fallback


def normalize_phone(value: str) -> str:
    """Exact-match form of a phone number: digits only, leading + kept."""
    digits = _PHONE_SEPARATORS.sub("", value or "")
    return digits.lower()


def build_indicators(*, domain=None, brand=None, sender_domain=None, contacts=None) -> list:
    """
    The exact values a report can be linked on. Anything missing is simply
    absent - a report with no shared value never links to anything.
    """
    indicators = []

    def add(kind: str, value):
        if value and isinstance(value, str):
            value = value.strip().lower()
            if value:
                indicators.append({"kind": kind, "value": value})

    add("domain", domain)
    add("brand", brand)

    contacts = contacts or {}
    for phone in contacts.get("phones") or []:
        add("phone", normalize_phone(phone))
    for upi in contacts.get("upi_ids") or []:
        add("upi", upi)
    for link in contacts.get("payment_links") or []:
        add("payment", link)

    add("sender_domain", sender_domain)

    unique = []
    seen = set()
    for item in indicators:
        key = (item["kind"], item["value"])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique


def _indicator_text(kind: str, value: str) -> str:
    return f"{INDICATOR_LABELS.get(kind, kind)}: {value}"


def _priority(kind: str) -> int:
    return INDICATOR_PRIORITY.index(kind) if kind in INDICATOR_PRIORITY else len(INDICATOR_PRIORITY)


def record_report(
    *,
    report_id: str,
    input_type: str,
    input_text: str,
    final_url=None,
    domain=None,
    brand=None,
    risk_class=None,
    risk_score=None,
    indicators=None,
    evidence=None,
    report=None,
    created_at=None,
) -> str:
    """Stores one report. Returns the created_at stamp that was written."""
    if input_type not in INPUT_TYPES:
        raise ValueError(f"unknown input_type: {input_type}")

    created_at = created_at or utc_now_iso()
    indicators = indicators or []

    with get_db() as conn:
        conn.execute(
            """INSERT INTO reports (
                   id, created_at, input_type, input_text, final_url, domain, brand,
                   risk_class, risk_score, indicators_json, evidence_json, report_json
               ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                report_id,
                created_at,
                input_type,
                (input_text or "")[:8000],
                final_url,
                domain,
                brand,
                risk_class,
                risk_score,
                json.dumps(indicators),
                json.dumps(evidence or []),
                json.dumps(report or {}),
            ),
        )
        conn.commit()

    return created_at


def find_related(new_indicators, exclude_id=None, new_risk_class=None, scan_limit: int = 200) -> list:
    """
    Earlier reports that share at least one indicator *exactly* with the new
    one. Purely set intersection - no fuzzy or semantic comparison.
    """
    wanted = {(item["kind"], item["value"]) for item in (new_indicators or []) if item.get("value")}
    if not wanted:
        return []

    with get_db() as conn:
        rows = conn.execute(
            """SELECT id, created_at, input_type, input_text, risk_class, indicators_json
               FROM reports
               ORDER BY created_at DESC, rowid DESC
               LIMIT ?""",
            (scan_limit,),
        ).fetchall()

    related = []
    for row in rows:
        if exclude_id and row["id"] == exclude_id:
            continue

        try:
            stored = json.loads(row["indicators_json"] or "[]")
        except ValueError:
            continue

        shared = [
            (item.get("kind"), item.get("value"))
            for item in stored
            if item.get("kind") and item.get("value")
            and (item["kind"], item["value"]) in wanted
        ]
        if not shared:
            continue

        # Never present two clean reports as a campaign.
        if new_risk_class in CLEAN_RISK_CLASSES and row["risk_class"] in CLEAN_RISK_CLASSES:
            continue

        shared.sort(key=lambda pair: _priority(pair[0]))
        related.append(
            {
                "id": row["id"],
                "input_type": row["input_type"],
                "created_at": row["created_at"],
                "input_text": row["input_text"],
                "risk_class": row["risk_class"],
                "shared_indicator": _indicator_text(*shared[0]),
                "shared_indicators": [_indicator_text(kind, value) for kind, value in shared],
            }
        )

    return related


def campaign_summary(related: list) -> str | None:
    """
    One plain-language line describing the link. Deterministic wording; the
    LLM may rephrase it elsewhere, but it never decides the match itself.
    """
    if not related:
        return None

    kinds = {}
    for entry in related:
        for text in entry.get("shared_indicators") or [entry.get("shared_indicator")]:
            kind = text.split(":", 1)[0]
            kinds.setdefault(kind, set()).add(text.split(":", 1)[-1].strip())

    parts = []
    for kind in INDICATOR_PRIORITY:
        label = INDICATOR_LABELS[kind]
        values = kinds.get(label)
        if values:
            shown = ", ".join(sorted(values)[:3])
            parts.append(f"{label} ({shown})")

    count = len(related)
    noun = "report" if count == 1 else "reports"
    return f"{count} earlier {noun} linked by {'; '.join(parts)}"


def list_reports(limit: int = 50) -> list:
    """Stored reports, newest first. The full JSON is omitted to keep this light."""
    limit = max(1, min(int(limit or 50), 200))
    with get_db() as conn:
        rows = conn.execute(
            """SELECT id, created_at, input_type, input_text, final_url, domain, brand,
                      risk_class, risk_score
               FROM reports
               ORDER BY created_at DESC, rowid DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_raw_report(report_id: str):
    """
    The exact JSON that was stored, without recomputed decorations. This is
    what gets hashed for on-chain registration, so the digest stays stable.
    """
    with get_db() as conn:
        row = conn.execute(
            "SELECT report_json FROM reports WHERE id = ?", (report_id,)
        ).fetchone()

    if row is None:
        return None

    try:
        return json.loads(row["report_json"] or "{}")
    except ValueError:
        return {}


def get_report(report_id: str):
    """One stored report (full JSON) with its related_reports, or None."""
    with get_db() as conn:
        row = conn.execute(
            """SELECT id, created_at, input_type, input_text, final_url, domain, brand,
                      risk_class, risk_score, indicators_json, evidence_json, report_json
               FROM reports WHERE id = ?""",
            (report_id,),
        ).fetchone()

    if row is None:
        return None

    try:
        report = json.loads(row["report_json"] or "{}")
    except ValueError:
        report = {}

    try:
        indicators = json.loads(row["indicators_json"] or "[]")
    except ValueError:
        indicators = []

    if not isinstance(report, dict):
        report = {}

    report.setdefault("email_id", row["id"])
    report.setdefault("id", row["id"])
    report["input_type"] = row["input_type"] or report.get("input_type")
    report["created_at"] = row["created_at"]
    report.setdefault("risk_class", row["risk_class"])
    if "related_reports" not in report:
        report["related_reports"] = find_related(indicators, exclude_id=row["id"])

    return report
