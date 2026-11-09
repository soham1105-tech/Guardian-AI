import asyncio

import pytest
from fastapi.testclient import TestClient

from app.database import init_db
from app.services import message_analyzer, reports_store
from app.services.reports_store import (
    build_indicators,
    campaign_summary,
    find_related,
    get_report,
    list_reports,
    record_report,
)


@pytest.fixture()
def db(tmp_path, monkeypatch):
    import app.database as database

    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "test.db"))
    init_db()
    return database


@pytest.fixture()
def client(db):
    from app.main import app

    with TestClient(app) as test_client:
        yield test_client


def _store(report_id, *, input_type="url", input_text=None, domain=None, brand=None,
           contacts=None, sender_domain=None, risk_class="High Risk", risk_score=7.9,
           created_at=None):
    indicators = build_indicators(
        domain=domain, brand=brand, contacts=contacts, sender_domain=sender_domain
    )
    record_report(
        report_id=report_id,
        input_type=input_type,
        input_text=input_text or f"report {report_id}",
        domain=domain,
        brand=brand,
        risk_class=risk_class,
        risk_score=risk_score,
        indicators=indicators,
        evidence=[],
        report={"email_id": report_id, "risk_class": risk_class},
        created_at=created_at,
    )
    return indicators


# --------------------------------------------------------------------------
# Indicator + summary helpers (no DB)
# --------------------------------------------------------------------------

def test_build_indicators_normalises_and_dedupes():
    indicators = build_indicators(
        domain="SBI-KYC-VERIFY.XYZ",
        brand="SBI",
        contacts={
            "phones": ["+91 98765 43210", "+919876543210"],
            "upi_ids": ["fraud@ybl"],
            "payment_links": ["https://paytm.me/abc"],
        },
        sender_domain="Mail.Example.COM",
    )

    values = {(item["kind"], item["value"]) for item in indicators}
    assert ("domain", "sbi-kyc-verify.xyz") in values
    assert ("brand", "sbi") in values
    assert ("upi", "fraud@ybl") in values
    assert ("payment", "https://paytm.me/abc") in values
    assert ("sender_domain", "mail.example.com") in values
    # both phone spellings collapse to one exact-match value
    assert [v for k, v in values if k == "phone"] == ["+919876543210"]


def test_build_indicators_without_values_is_empty():
    assert build_indicators() == []


def test_campaign_summary_names_the_shared_indicator():
    related = [{"shared_indicator": "shared redirect domain: sbi-kyc-verify.xyz",
                "shared_indicators": ["shared redirect domain: sbi-kyc-verify.xyz"]}]
    summary = campaign_summary(related)

    assert "1 earlier report" in summary
    assert "sbi-kyc-verify.xyz" in summary
    assert campaign_summary([]) is None


# --------------------------------------------------------------------------
# Correlation rules (exact matches only)
# --------------------------------------------------------------------------

def test_same_redirect_domain_links_reports(db):
    first = _store("r1", domain="sbi-kyc-verify.xyz", input_text="http://sbi-kyc-verify.xyz/login")
    related = find_related(first, exclude_id="r2")

    assert [entry["id"] for entry in related] == ["r1"]
    assert related[0]["shared_indicator"] == "shared redirect domain: sbi-kyc-verify.xyz"
    assert related[0]["input_text"] == "http://sbi-kyc-verify.xyz/login"
    assert related[0]["risk_class"] == "High Risk"


def test_same_brand_links_reports(db):
    _store("r1", domain="sbi-verify.xyz", brand="sbi")
    related = find_related(build_indicators(domain="other-domain.tld", brand="sbi"), exclude_id="r2")

    assert [entry["id"] for entry in related] == ["r1"]
    assert related[0]["shared_indicator"] == "shared impersonated brand: sbi"


def test_same_phone_upi_or_payment_link_links_reports(db):
    _store("r-phone", input_type="message", contacts={"phones": ["+91 98765 43210"]})
    _store("r-upi", input_type="message", contacts={"upi_ids": ["fraud@ybl"]})
    _store("r-pay", input_type="message", contacts={"payment_links": ["https://paytm.me/abc"]})

    assert [e["id"] for e in find_related(build_indicators(contacts={"phones": ["+919876543210"]}),
                                         exclude_id="new")] == ["r-phone"]
    assert [e["id"] for e in find_related(build_indicators(contacts={"upi_ids": ["FRAUD@ybl"]}),
                                         exclude_id="new")] == ["r-upi"]
    assert [e["id"] for e in find_related(build_indicators(contacts={"payment_links": ["https://paytm.me/abc"]}),
                                         exclude_id="new")] == ["r-pay"]


def test_same_sender_domain_links_email_reports(db):
    _store("mail-1", input_type="email", sender_domain="mail.example.com")
    related = find_related(build_indicators(sender_domain="MAIL.EXAMPLE.COM"), exclude_id="mail-2")

    assert [entry["id"] for entry in related] == ["mail-1"]
    assert related[0]["shared_indicator"] == "shared sender domain: mail.example.com"


def test_unrelated_reports_are_never_linked(db):
    _store("phish", domain="sbi-kyc-verify.xyz", brand="sbi")

    assert find_related(build_indicators(domain="google.com"), exclude_id="clean") == []
    # a near-miss (different domain, same brand list entry) still matches only on brand
    assert [e["shared_indicator"] for e in find_related(
        build_indicators(domain="google.com", brand="sbi"), exclude_id="clean"
    )] == ["shared impersonated brand: sbi"]


def test_two_clean_reports_are_not_a_campaign(db):
    _store("google-1", domain="google.com", risk_class="Low Risk", risk_score=0.0)

    assert find_related(build_indicators(domain="google.com"), exclude_id="google-2",
                        new_risk_class="Low Risk") == []
    # ...but a suspicious report sharing that domain still links to it
    assert [e["id"] for e in find_related(build_indicators(domain="google.com"),
                                          exclude_id="new", new_risk_class="High Risk")] == ["google-1"]


def test_multiple_shared_indicators_list_the_most_meaningful_first(db):
    _store("both", domain="sbi-kyc-verify.xyz", brand="sbi")
    related = find_related(build_indicators(domain="sbi-kyc-verify.xyz", brand="sbi"), exclude_id="new")

    assert related[0]["shared_indicator"] == "shared redirect domain: sbi-kyc-verify.xyz"
    assert len(related[0]["shared_indicators"]) == 2


# --------------------------------------------------------------------------
# Storage + query API
# --------------------------------------------------------------------------

def test_reports_are_listed_newest_first_and_limited(db):
    _store("old", created_at="2026-01-01T00:00:00Z")
    _store("new", created_at="2026-02-01T00:00:00Z")
    _store("mid", created_at="2026-01-15T00:00:00Z")

    assert [row["id"] for row in list_reports()] == ["new", "mid", "old"]
    assert [row["id"] for row in list_reports(limit=2)] == ["new", "mid"]


def test_report_detail_returns_full_report_with_related(db):
    _store("earlier", domain="sbi-kyc-verify.xyz")
    _store("later", domain="sbi-kyc-verify.xyz")

    detail = get_report("later")
    assert detail["email_id"] == "later"
    assert [entry["id"] for entry in detail["related_reports"]] == ["earlier"]
    assert get_report("does-not-exist") is None


def test_message_analysis_extracts_contacts_and_scores_them():
    report = asyncio.run(
        message_analyzer.analyze_message(
            "Dear customer your account is blocked. Pay Rs 4999 to fraud@ybl or call +91 98765 43210"
        )
    )

    assert report["contacts"]["upi_ids"] == ["fraud@ybl"]
    # separators are collapsed so "+91 98765 43210" and "+919876543210" match exactly
    assert report["contacts"]["phones"] == ["+919876543210"]
    assert report["risk_report"]["breakdown"]["payment_contact_score"] > 0
    assert report["risk_class"] in ("Suspicious", "High Risk", "Confirmed Malicious")
    assert report["message_text"].startswith("Dear customer")


def test_payment_link_in_message_text_is_extracted():
    report = asyncio.run(
        message_analyzer.analyze_message("Pay now at https://paytm.me/abc to avoid suspension")
    )
    assert report["contacts"]["payment_links"] == ["https://paytm.me/abc"]


# --------------------------------------------------------------------------
# HTTP endpoints
# --------------------------------------------------------------------------

def test_api_reports_endpoints(client):
    _store("one", domain="sbi-kyc-verify.xyz", input_text="http://sbi-kyc-verify.xyz/login")

    listing = client.get("/api/reports")
    assert listing.status_code == 200
    assert [row["id"] for row in listing.json()] == ["one"]
    assert listing.json()[0]["input_text"] == "http://sbi-kyc-verify.xyz/login"

    detail = client.get("/api/reports/one")
    assert detail.status_code == 200
    assert detail.json()["email_id"] == "one"

    assert client.get("/api/reports/missing").status_code == 404


def test_api_analyze_message_links_to_earlier_url_report(client, monkeypatch):
    """The full flow from the spec: URL report first, then the pasted message."""

    async def fake_investigate(url):
        return {
            "investigation_type": "link",
            "verdict": "High Risk",
            "risk_class": "High Risk",
            "risk_score": 8.4,
            "summary": "stub",
            "indicators": [],
            "evidence": [],
            "recommendations": [],
            "checks": {
                "registered_domain": "sbi-kyc-verify.xyz",
                "domain_intel": {"brand": "sbi"},
                "redirects": {"final_url": url},
            },
            "url_analysis": [],
            "ioc_summary": {"ips": [], "domains": ["sbi-kyc-verify.xyz"], "urls": [url],
                            "emails": [], "hashes": []},
            "threat_intel": {"results": {},
                             "summary": {"total_iocs_checked": 0, "malicious_ioc_count": 0,
                                         "malicious_iocs": [], "max_confidence": 0}},
            "mitre_techniques": [],
            "risk_report": {"score": 84, "category": "CRITICAL", "breakdown": {}},
            "ai_verdict": None,
        }

    monkeypatch.setattr(message_analyzer, "investigate_link", fake_investigate)

    _store("url-report", domain="sbi-kyc-verify.xyz", brand="sbi",
           input_text="http://sbi-kyc-verify.xyz/login", risk_class="High Risk")

    response = client.post(
        "/api/analyze-message",
        json={"text": "Dear customer, your SBI account will be blocked today. "
                      "Verify KYC now at http://sbi-kyc-verify.xyz/login"},
    )
    assert response.status_code == 200

    body = response.json()
    related = body["related_reports"]
    assert [entry["id"] for entry in related] == ["url-report"]
    assert related[0]["shared_indicator"] == "shared redirect domain: sbi-kyc-verify.xyz"
    assert body["campaign_summary"]
    assert body["input_type"] == "message"

    # the message itself is now a stored report with its own link back
    assert [row["id"] for row in client.get("/api/reports").json()] == [body["email_id"], "url-report"]
    stored = client.get(f"/api/reports/{body['email_id']}").json()
    assert [entry["id"] for entry in stored["related_reports"]] == ["url-report"]


def test_api_analyze_message_rejects_blank_text(client):
    assert client.post("/api/analyze-message", json={"text": "   "}).status_code == 422
    assert client.post("/api/analyze-message", json={}).status_code == 422


def test_clean_report_gets_no_related_reports(client, monkeypatch):
    async def fake_investigate(url):
        return {
            "investigation_type": "link", "verdict": "Low Risk", "risk_class": "Low Risk",
            "risk_score": 0.0, "summary": "stub", "indicators": [], "evidence": [],
            "recommendations": [],
            "checks": {"registered_domain": "google.com", "domain_intel": {"brand": None},
                       "redirects": {"final_url": url}},
            "url_analysis": [], "ioc_summary": {"ips": [], "domains": ["google.com"],
                                                "urls": [url], "emails": [], "hashes": []},
            "threat_intel": {"results": {}, "summary": {"total_iocs_checked": 0,
                                                        "malicious_ioc_count": 0,
                                                        "malicious_iocs": [], "max_confidence": 0}},
            "mitre_techniques": [],
            "risk_report": {"score": 0, "category": "SAFE", "breakdown": {}},
            "ai_verdict": None,
        }

    monkeypatch.setattr(message_analyzer, "investigate_link", fake_investigate)

    _store("phish", domain="sbi-kyc-verify.xyz", brand="sbi", risk_class="High Risk")
    response = client.post("/api/analyze-message", json={"text": "hello, just checking in"})

    assert response.status_code == 200
    assert response.json()["related_reports"] == []
    assert "campaign_summary" not in response.json()
