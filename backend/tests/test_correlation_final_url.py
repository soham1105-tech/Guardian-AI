"""Correlation uses the *final* redirect domain, not the submitted one."""

import pytest
from fastapi.testclient import TestClient

from app.database import init_db
from app.services import link_investigator
from app.services.reports_store import final_registered_domain, get_report


@pytest.fixture()
def client(tmp_path, monkeypatch):
    import app.database as database
    import app.api.investigate as api_module

    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "test.db"))
    init_db()
    from app.main import app

    with TestClient(app) as test_client:
        yield test_client


def test_final_registered_domain_prefers_the_redirect_target():
    assert final_registered_domain("https://login.sbi-kyc-verify.xyz/a") == "sbi-kyc-verify.xyz"
    assert final_registered_domain(None, "submitted.example") == "submitted.example"
    assert final_registered_domain("not a url", "submitted.example") == "submitted.example"


def _stub_report(final_url, submitted_domain):
    return {
        "investigation_type": "link",
        "verdict": "High Risk",
        "risk_class": "High Risk",
        "risk_score": 8.0,
        "summary": "stub",
        "indicators": [],
        "evidence": [],
        "recommendations": [],
        "checks": {
            "display_url": submitted_domain,
            "normalized_url": f"https://{submitted_domain}/",
            "registered_domain": submitted_domain,
            "domain_intel": {"brand": None},
            "redirects": {"final_url": final_url},
        },
        "url_analysis": [],
        "ioc_summary": {"ips": [], "domains": [], "urls": [], "emails": [], "hashes": []},
        "threat_intel": {"results": {}, "summary": {"total_iocs_checked": 0,
                                                    "malicious_ioc_count": 0,
                                                    "malicious_iocs": [], "max_confidence": 0}},
        "mitre_techniques": [],
        "risk_report": {"score": 80, "category": "HIGH", "breakdown": {}},
        "ai_verdict": None,
    }


def test_redirect_targets_are_correlated_not_the_submitted_domain(client, monkeypatch):
    """Two short links that redirect to the same domain must be linked."""
    redirects = {"https://short-one.example/abc": "https://campaign.kyc-verify.xyz/landing",
                 "https://tiny-two.example/xyz": "https://campaign.kyc-verify.xyz/other"}

    async def fake_investigate(url):
        return _stub_report(redirects[url], url.split("/")[2])

    monkeypatch.setattr(link_investigator, "investigate_link", fake_investigate)
    monkeypatch.setattr("app.api.investigate.investigate_link", fake_investigate)

    first = client.post("/api/investigate", json={"url": "https://short-one.example/abc"})
    assert first.status_code == 200
    assert first.json()["related_reports"] == []

    second = client.post("/api/investigate", json={"url": "https://tiny-two.example/xyz"})
    assert second.status_code == 200

    related = second.json()["related_reports"]
    assert [entry["id"] for entry in related] == [first.json()["email_id"]]
    assert related[0]["shared_indicator"] == "shared redirect domain: kyc-verify.xyz"

    stored = get_report(second.json()["email_id"])
    assert stored["related_reports"][0]["id"] == first.json()["email_id"]
