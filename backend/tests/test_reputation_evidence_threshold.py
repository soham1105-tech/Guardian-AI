import asyncio

import pytest

from app.services.link_investigator import _combine, investigate_link, risk_class_for
from app.services.threat_intel.evidence import (
    INFORMATIONAL_SINGLE_VENDOR_NOTE,
    VENDOR_EVIDENCE_THRESHOLD,
    has_qualifying_ti_match,
)
from app.services.threat_intel.provider_manager import summarize_threat_intel
from app.services.threat_intel.virustotal import VirusTotalProvider


class _FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _FakeClient:
    def __init__(self, payload):
        self._payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url, headers=None):
        return _FakeResponse(self._payload)


def _vt_payload(malicious: int, suspicious: int = 0, harmless: int = 90):
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": harmless,
                    "undetected": 0,
                }
            }
        }
    }


def _tls_stub():
    return {
        "analyzed": True, "url": "https://example.com/", "host": "example.com", "port": 443,
        "https": True, "status": "valid", "status_label": "valid",
        "certificate": {"subject": "CN=example.com", "issuer": "O=Test CA,CN=Test CA",
                       "issuer_common_name": "Test CA", "issuer_organization": "Test CA",
                       "serial_number": "01", "not_before": "2026-01-01T00:00:00Z",
                       "not_after": "2026-12-31T00:00:00Z", "signature_algorithm": "sha256WithRSAEncryption",
                       "public_key_type": "RSA", "public_key_bits": 2048, "sha256_fingerprint": "00",
                       "san": ["example.com"], "san_ip": [], "san_count": 1, "expired": False,
                       "not_yet_valid": False, "self_signed": False, "days_remaining": 50},
        "hostname": {"matches": True, "matched_value": "example.com", "checked_host": "example.com"},
        "chain": {"trusted": True, "verification_error": None, "protocol": "TLSv1.3",
                  "cipher": "TLS_AES_128_GCM_SHA256 (128 bits)", "note": "stub"},
        "compromised_ca": {"matched": False, "name": None, "reason": None},
        "ct": {"available": False, "query": None, "source": "https://crt.sh/", "certificate_count": 0,
               "truncated": False, "count_note": "CT log unavailable: stub", "window_days": 7,
               "recently_issued_count": 0, "recently_issued": [], "oldest_not_before": None,
               "newest_not_before": None, "error": "CT log unavailable: stub"},
        "findings": [], "score": 0, "note": "A valid certificate does not mean the website is safe", "error": None,
    }


def _chain(url):
    return {
        "hops": [{"hop": 1, "url": url, "status": 200, "content_type": "text/html", "location": None,
                  "bytes_read": 10, "truncated": False, "title": "Example", "server": "nginx",
                  "headers": {}, "elapsed_ms": 5, "error": None}],
        "hop_count": 1, "redirect_count": 0, "final_url": url, "final_host": url.split("/")[2],
        "submitted_host": url.split("/")[2], "domain_changed": False, "scheme_downgrade": False,
        "limit_exceeded": False, "loop_detected": False, "page_title": "Example", "error": None,
    }


def _offline(monkeypatch, reputation_results):
    from app.services import link_investigator as li
    from app.services import ssrf_guard

    async def fake_validate(url, timeout=5):
        host = url.split("/")[2]
        return {"allowed": True, "blocked": False, "resolved": True, "reason": "", "host": host, "ips": ["93.184.216.34"]}

    async def fake_dns(host, timeout=5, fallback_host=None):
        return {"host": host, "resolved": True, "records": {"A": ["93.184.216.34"]},
                "addresses": ["93.184.216.34"], "mx": [], "error": None, "error_kind": None}

    async def fake_chain(url, max_hops=5, timeout=5, max_bytes=1024 * 1024):
        return _chain(url)

    async def fake_reputation(normalized, ips):
        summary = summarize_threat_intel(reputation_results)
        return {
            "ioc_summary": {"urls": [normalized["url"]], "domains": [normalized["registered_domain"]],
                            "ips": [], "emails": [], "hashes": []},
            "results": reputation_results,
            "summary": summary,
            "providers_with_clean_results": [],
            "providers_that_flagged": [v["provider"] for verdicts in reputation_results.values() for v in verdicts if v.get("malicious") or v.get("qualifying")],
            "providers_configured": ["VirusTotal"],
        }

    async def fake_tls(url, host, **kwargs):
        return _tls_stub()

    async def fake_probes(base_url, timeout=5, max_bytes=64 * 1024):
        return [{"path": f"/{path}", "url": f"{base_url.rstrip('/')}/{path}", "status": 404,
                 "exposed": False, "bytes_read": 0, "content_type": "text/html", "error": None}
                for path in ssrf_guard.SENSITIVE_PROBE_PATHS]

    monkeypatch.setattr(li, "validate_target", fake_validate)
    monkeypatch.setattr(li, "resolve_domain", fake_dns)
    monkeypatch.setattr(li, "fetch_redirect_chain", fake_chain)
    monkeypatch.setattr(li, "_collect_reputation", fake_reputation)
    monkeypatch.setattr(li, "analyze_tls", fake_tls)
    monkeypatch.setattr(li, "probe_sensitive_paths", fake_probes)
    monkeypatch.setattr(li, "get_ai_verdict", lambda evidence: {
        "classification": "test", "confidence": 50, "explanation": "stub", "recommended_action": "stub",
    })


# (a) mocked VT 1/92 => informational, 0 score contribution, Low Risk for clean URL
def test_single_vendor_vt_flag_is_informational_not_evidence(monkeypatch):
    import httpx
    from app.config import settings
    from app.services.threat_intel import virustotal as vt_mod

    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(httpx, "AsyncClient", lambda timeout=10: _FakeClient(_vt_payload(malicious=1, suspicious=0, harmless=91)))

    verdict = asyncio.run(VirusTotalProvider().check("domain", "google.com"))

    assert verdict.checked is True
    assert verdict.malicious is False
    assert verdict.confidence == 0
    assert verdict.vendor_count == 1
    assert verdict.qualifying is False
    assert verdict.detail == INFORMATIONAL_SINGLE_VENDOR_NOTE

    results = {"google.com": [{"provider": "VirusTotal", "malicious": False, "confidence": 0,
                               "detail": INFORMATIONAL_SINGLE_VENDOR_NOTE, "checked": True,
                               "vendor_count": 1, "qualifying": False}]}
    summary = summarize_threat_intel(results)
    assert summary["malicious_ioc_count"] == 0
    assert summary["malicious_iocs"] == []
    assert has_qualifying_ti_match(results) is False


def test_single_vendor_flag_does_not_make_clean_url_high_risk(monkeypatch):
    _offline(monkeypatch, {
        "www.google.com": [
            {"provider": "VirusTotal", "malicious": False, "confidence": 0,
             "detail": INFORMATIONAL_SINGLE_VENDOR_NOTE, "checked": True, "vendor_count": 1, "qualifying": False},
            {"provider": "AlienVault OTX", "malicious": False, "confidence": 0,
             "detail": "No threat pulses found", "checked": True},
        ]
    })
    report = asyncio.run(investigate_link("https://www.google.com"))
    assert report["risk_class"] == "Low Risk"
    assert report["verdict"] == "Low Risk"
    assert report["threat_intel"]["summary"]["malicious_ioc_count"] == 0
    # informational note present
    rep_text = " ".join(e.get("finding", "") + " " + e.get("detail", "") for e in report["evidence"] if e.get("source") == "Reputation")
    assert "below the evidence threshold of 2" in rep_text


# (b) mocked VT 3/92 => evidence counted, score rises, indicator present
def test_multi_vendor_vt_flags_count_as_evidence(monkeypatch):
    import httpx
    from app.config import settings
    from app.services.threat_intel import virustotal as vt_mod

    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "test-key")
    monkeypatch.setattr(httpx, "AsyncClient", lambda timeout=10: _FakeClient(_vt_payload(malicious=3, suspicious=0, harmless=89)))

    verdict = asyncio.run(VirusTotalProvider().check("url", "https://evil.example/"))

    assert verdict.checked is True
    assert verdict.malicious is True
    assert verdict.vendor_count == 3
    assert verdict.qualifying is True
    assert "3/" in verdict.detail


def test_multi_vendor_flags_raise_score_and_add_indicator(monkeypatch):
    _offline(monkeypatch, {
        "evil.example": [
            {"provider": "VirusTotal", "malicious": True, "confidence": 3,
             "detail": "3/92 vendors flagged as malicious", "checked": True, "vendor_count": 3, "qualifying": True},
        ]
    })
    report = asyncio.run(investigate_link("https://evil.example/"))
    assert report["threat_intel"]["summary"]["malicious_ioc_count"] >= 1
    assert report["risk_score"] >= 8.5  # qualifying scan verdict floors reputation
    assert any(i.get("type") == "reputation" for i in report["indicators"])
    assert report["risk_class"] == "Confirmed Malicious"


# (c) class-mapping unit tests
@pytest.mark.parametrize(
    "score_100,qual_ti,expected",
    [
        (20, False, "Low Risk"),      # 2.0
        (50, False, "Suspicious"),    # 5.0
        (80, False, "High Risk"),     # 8.0
        (90, True, "Confirmed Malicious"),
        (90, False, "High Risk"),
    ],
)
def test_risk_class_mapping_boundaries(score_100, qual_ti, expected):
    assert risk_class_for(score_100, has_qualifying_threat_intel=qual_ti) == expected


def test_risk_class_inconclusive_when_no_usable_data():
    assert risk_class_for(0, has_qualifying_threat_intel=False, no_usable_data=True) == "Inconclusive"
