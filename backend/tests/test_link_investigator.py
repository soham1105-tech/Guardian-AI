import asyncio

import pytest
from fastapi.testclient import TestClient

from app.database import init_db
from app.services import link_investigator as li
from app.services import ssrf_guard
from app.services.domain_intel import check_domain
from app.services.link_investigator import _combine, investigate_link
from app.services.ssrf_guard import SSRFBlockedError, validate_target
from app.services.url_normalizer import InvalidURLError, normalize_url


# --------------------------------------------------------------------------
# URL normalisation
# --------------------------------------------------------------------------

def test_normalization_lowercases_host_and_strips_tracking_params():
    result = normalize_url("HTTPS://WWW.Example.COM:443/A/b?utm_source=x&fbclid=y&id=7#frag")

    assert result["host"] == "www.example.com"
    assert result["url"] == "https://www.example.com/A/b?id=7"
    assert result["tracking_params_removed"] == ["utm_source", "fbclid"]
    assert result["registered_domain"] == "example.com"


def test_normalization_assumes_https_when_scheme_missing():
    result = normalize_url("sbi.co.in/login")
    assert result["url"] == "https://sbi.co.in/login"
    assert result["scheme_assumed"] is True


def test_punycode_host_is_decoded_for_display():
    # "pаypal.com" with a Cyrillic 'а'
    result = normalize_url("https://xn--pypal-4ve.com/login")

    assert result["host"] == "xn--pypal-4ve.com"
    assert result["unicode_host"] == "pаypal.com"
    assert result["homograph"]["is_punycode"] is True
    assert result["homograph"]["suspicious"] is True
    assert "pаypal.com" in result["display_url"]


@pytest.mark.parametrize(
    "raw",
    ["", "   ", "ftp://example.com/x", "javascript:alert(1)", "not-a-domain", "https://exa mple.com/"],
)
def test_invalid_urls_are_rejected(raw):
    with pytest.raises(InvalidURLError):
        normalize_url(raw)


# --------------------------------------------------------------------------
# Domain intelligence
# --------------------------------------------------------------------------

def test_official_brand_domain_is_clean():
    assert check_domain(normalize_url("https://www.google.com"))["score"] == 0
    assert check_domain(normalize_url("https://sbi.co.in/web/personal-banking"))["score"] == 0


def test_brand_plus_suspicious_tld_is_flagged():
    intel = check_domain(normalize_url("http://sbi-kyc-verify.xyz/login"))
    kinds = {item["type"] for item in intel["indicators"]}

    assert intel["brand"] == "sbi"
    assert intel["suspicious_tld"] is True
    assert "brand_impersonation" in kinds
    assert "suspicious_tld" in kinds
    assert intel["score"] >= 60


def test_typosquat_is_detected():
    intel = check_domain(normalize_url("https://hdfcbannk.com/login"))
    assert "typosquatting" in {item["type"] for item in intel["indicators"]}


# --------------------------------------------------------------------------
# SSRF guard
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:8000/admin",
        "http://10.1.2.3/",
        "http://192.168.1.1/",
        "http://172.20.0.1/",
        "http://[::1]/",
        "http://localhost/admin",
        "http://metadata.google.internal/computeMetadata/v1/",
    ],
)
def test_private_and_local_targets_are_blocked(url):
    result = asyncio.run(validate_target(url, timeout=1))
    assert result["allowed"] is False
    assert result["blocked"] is True


def test_public_ip_literal_is_allowed():
    result = asyncio.run(validate_target("http://93.184.216.34/", timeout=1))
    assert result["allowed"] is True
    assert result["blocked"] is False


def test_investigate_link_raises_for_metadata_endpoint():
    with pytest.raises(SSRFBlockedError):
        asyncio.run(investigate_link("http://169.254.169.254/latest/meta-data/"))


def test_redirect_to_metadata_is_blocked_before_it_is_fetched(monkeypatch):
    """A public page that redirects to cloud metadata must not be followed."""
    from app.services import ssrf_guard

    start = "https://public.example/start"
    fetched = []
    real_validate = ssrf_guard.validate_target

    async def guarded_validate(url, timeout=5):
        if url == start:
            return {
                "allowed": True, "blocked": False, "resolved": True, "reason": "",
                "host": "public.example", "ips": ["93.184.216.34"],
            }
        return await real_validate(url, timeout=timeout)

    async def fake_safe_get(url, timeout, max_bytes):
        fetched.append(url)
        return {
            "url": url, "status": 302, "content_type": "text/html",
            "location": "http://169.254.169.254/latest/meta-data/",
            "bytes_read": 0, "truncated": False, "title": None,
            "server": None, "error": None,
        }

    monkeypatch.setattr(ssrf_guard, "validate_target", guarded_validate)
    monkeypatch.setattr(ssrf_guard, "_safe_get", fake_safe_get)

    chain = asyncio.run(ssrf_guard.fetch_redirect_chain(start))

    assert fetched == [start]  # only the public hop was ever requested
    assert len(chain["hops"]) == 2
    blocked_hop = chain["hops"][1]
    assert blocked_hop["status"] is None
    assert "SSRF" in blocked_hop["error"]
    assert "blocked" in (chain["error"] or "").lower()


def test_response_body_is_capped_at_one_megabyte():
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    body = b"<html><title>Big</title>" + b"A" * (2 * 1024 * 1024)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *args):  # keep pytest output clean
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/big"
        hop = asyncio.run(ssrf_guard._safe_get(url, timeout=5, max_bytes=1024 * 1024))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert hop["status"] == 200
    assert hop["bytes_read"] == 1024 * 1024
    assert hop["truncated"] is True
    assert hop["title"] == "Big"


def test_redirect_findings_score_unrelated_domain_and_downgrade():
    chain = _chain("https://brand.example/login", domain_changed=True, scheme_downgrade=True,
                   final_host="evil.example", final_url="http://evil.example/login", redirect_count=1)
    score, indicators, evidence = li._redirect_findings(chain)

    kinds = {item["type"] for item in indicators}
    assert score >= 35
    assert "redirect" in kinds
    assert any("unrelated domain" in line for line in evidence)


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------

def test_single_pulse_otx_is_below_threshold_and_does_not_count():
    results = {
        "example.com": [
            {"provider": "AlienVault OTX", "malicious": False, "confidence": 0,
             "detail": "1 community threat-intel pulse (below the evidence threshold of 2) — not counted toward the score",
             "checked": True, "vendor_count": 1, "qualifying": False}
        ]
    }
    confirmed, score = li._reputation_strength(results)

    assert confirmed is False
    assert score == 0


def test_qualifying_scan_provider_verdict_confirms_malicious():
    # URLhaus has no vendor count; it qualifies when corroborated by a second independent source.
    results = {
        "https://evil.example/payload": [
            {"provider": "URLhaus", "malicious": True, "confidence": 90,
             "detail": "Listed in URLhaus as 'malware_download' (status: online)", "checked": True,
             "vendor_count": None, "qualifying": False},
            {"provider": "VirusTotal", "malicious": True, "confidence": 10,
             "detail": "4/92 vendors flagged as malicious", "checked": True,
             "vendor_count": 4, "qualifying": True},
        ]
    }
    confirmed, score = li._reputation_strength(results)

    assert confirmed is True
    assert score >= li.REPUTATION_MALICIOUS_FLOOR


def test_official_short_domains_are_not_typosquats():
    for url in ("https://youtu.be/dQw4w9WgXcQ", "https://www.youtube.com/watch?v=1"):
        intel = check_domain(normalize_url(url))
        assert intel["brand"] is None
        assert intel["score"] == 0
        assert intel["indicators"] == []


def test_combine_lets_the_strongest_signal_dominate():
    assert _combine({"a": 0, "b": 0}) == 0
    assert _combine({"a": 60, "b": 0, "c": 0}) == 60
    assert _combine({"a": 60, "b": 40}) == 68
    assert _combine({"a": 90, "b": 90, "c": 90}) == 100


# --------------------------------------------------------------------------
# Full investigation, network-free
# --------------------------------------------------------------------------

def _tls_stub(*, status="valid", score=0, findings=None):
    return {
        "analyzed": True,
        "url": "https://example.com/",
        "host": "example.com",
        "port": 443,
        "https": True,
        "status": status,
        "status_label": status,
        "certificate": {
            "subject": "CN=example.com",
            "issuer": "O=Test CA,CN=Test CA",
            "issuer_common_name": "Test CA",
            "issuer_organization": "Test CA",
            "serial_number": "01",
            "not_before": "2026-01-01T00:00:00Z",
            "not_after": "2026-12-31T00:00:00Z",
            "signature_algorithm": "sha256WithRSAEncryption",
            "public_key_type": "RSA",
            "public_key_bits": 2048,
            "sha256_fingerprint": "00",
            "san": ["example.com"],
            "san_ip": [],
            "san_count": 1,
            "expired": status == "expired",
            "not_yet_valid": False,
            "self_signed": status == "self_signed",
            "days_remaining": None if status == "expired" else 50,
        },
        "hostname": {"matches": True, "matched_value": "example.com", "checked_host": "example.com"},
        "chain": {
            "trusted": True,
            "verification_error": None,
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_128_GCM_SHA256 (128 bits)",
            "note": "stub",
        },
        "compromised_ca": {"matched": False, "name": None, "reason": None},
        "ct": {
            "available": False,
            "query": None,
            "source": "https://crt.sh/",
            "certificate_count": 0,
            "truncated": False,
            "count_note": "CT log unavailable: stub",
            "window_days": 7,
            "recently_issued_count": 0,
            "recently_issued": [],
            "oldest_not_before": None,
            "newest_not_before": None,
            "error": "CT log unavailable: stub",
        },
        "findings": findings or [],
        "score": score,
        "note": "A valid certificate does not mean the website is safe",
        "error": None,
    }


def _offline_patches(monkeypatch, *, resolved, dns_error, chain, tls_section=None):
    async def fake_validate(url, timeout=5):
        return {
            "allowed": resolved,
            "blocked": False,
            "resolved": resolved,
            "reason": "" if resolved else "did not resolve",
            "host": url.split("/")[2],
            "ips": ["203.0.113.9"] if resolved else [],
        }

    async def fake_dns(host, timeout=5, fallback_host=None):
        return {
            "host": host,
            "resolved": resolved,
            "records": {"A": ["203.0.113.9"]} if resolved else {},
            "addresses": ["203.0.113.9"] if resolved else [],
            "mx": [],
            "error": dns_error,
            "error_kind": None if resolved else "nxdomain",
        }

    async def fake_chain(url, max_hops=5, timeout=5, max_bytes=1024 * 1024):
        return chain

    async def fake_reputation(normalized, ips):
        return {
            "ioc_summary": {"urls": [normalized["url"]], "domains": [normalized["registered_domain"]],
                            "ips": [], "emails": [], "hashes": []},
            "results": {},
            "summary": {"total_iocs_checked": 0, "malicious_ioc_count": 0, "malicious_iocs": [], "max_confidence": 0},
            "providers_with_clean_results": [],
            "providers_that_flagged": [],
            "providers_configured": [],
        }

    monkeypatch.setattr(li, "validate_target", fake_validate)
    monkeypatch.setattr(li, "resolve_domain", fake_dns)
    monkeypatch.setattr(li, "fetch_redirect_chain", fake_chain)
    async def fake_tls(url, host, **kwargs):
        return tls_section or _tls_stub()

    async def fake_probes(base_url, timeout=5, max_bytes=64 * 1024):
        return [
            {
                "path": f"/{path}",
                "url": f"{base_url.rstrip('/')}/{path}",
                "status": 404,
                "exposed": False,
                "bytes_read": 0,
                "content_type": "text/html",
                "error": None,
            }
            for path in ssrf_guard.SENSITIVE_PROBE_PATHS
        ]

    monkeypatch.setattr(li, "_collect_reputation", fake_reputation)
    monkeypatch.setattr(li, "probe_sensitive_paths", fake_probes)
    monkeypatch.setattr(li, "analyze_tls", fake_tls)
    monkeypatch.setattr(li, "get_ai_verdict", lambda evidence: {
        "classification": "test", "confidence": 50, "explanation": "stub", "recommended_action": "stub",
    })


def _chain(url, **overrides):
    base = {
        "hops": [{"hop": 1, "url": url, "status": 200, "content_type": "text/html", "location": None,
                  "bytes_read": 10, "truncated": False, "title": "Example", "server": "nginx",
                  "elapsed_ms": 5, "error": None}],
        "hop_count": 1,
        "redirect_count": 0,
        "final_url": url,
        "final_host": url.split("/")[2],
        "submitted_host": url.split("/")[2],
        "domain_changed": False,
        "scheme_downgrade": False,
        "limit_exceeded": False,
        "loop_detected": False,
        "page_title": "Example",
        "error": None,
    }
    base.update(overrides)
    return base


def test_investigation_of_unresolvable_typosquat_is_high_risk(monkeypatch):
    url = "http://sbi-kyc-verify.xyz/login"
    _offline_patches(
        monkeypatch,
        resolved=False,
        dns_error="NXDOMAIN — 'sbi-kyc-verify.xyz' does not exist in DNS",
        chain=_chain(url, status=None, error="'sbi-kyc-verify.xyz' did not resolve"),
    )

    report = asyncio.run(investigate_link(url))

    assert report["risk_report"]["category"] == "HIGH"
    assert report["verdict"] == "High Risk"
    assert report["risk_score"] == round(report["risk_report"]["score"] / 10, 1)
    kinds = {i["type"] for i in report["indicators"]}
    assert {"brand_impersonation", "suspicious_tld", "dns"} <= kinds
    # DNS failure must be evidence, not an error
    assert report["checks"]["dns"]["resolved"] is False
    assert any(e["source"] == "DNS" for e in report["evidence"])
    # email-compatible sections are present so the dashboard can render it
    for key in ("parsed", "header_analysis", "url_analysis", "attachment_analysis",
                "ioc_summary", "threat_intel", "mitre_techniques", "risk_report", "ai_verdict", "checks"):
        assert key in report


def test_investigation_of_clean_domain_is_low_risk(monkeypatch):
    _offline_patches(
        monkeypatch,
        resolved=True,
        dns_error=None,
        chain=_chain("https://www.google.com/"),
    )

    report = asyncio.run(investigate_link("https://www.google.com"))

    assert report["risk_report"]["category"] == "SAFE"
    assert report["verdict"] == "Low Risk"
    assert report["risk_report"]["score"] == 0
    assert report["indicators"] == []
    # a valid certificate never adds a penalty, but the disclaimer is always there
    assert report["checks"]["tls"]["score"] == 0
    assert report["checks"]["tls"]["note"] == "A valid certificate does not mean the website is safe"


def test_expired_certificate_raises_report_to_high_risk(monkeypatch):
    expired = _tls_stub(
        status="expired",
        score=75,
        findings=[
            {
                "type": "expired",
                "severity": "high",
                "evidence": "Certificate expired on 2015-04-12T23:59:59Z (3900 day(s) ago)",
                "detail": "An expired certificate means the HTTPS session cannot be authenticated.",
            }
        ],
    )
    _offline_patches(
        monkeypatch,
        resolved=True,
        dns_error=None,
        chain=_chain("https://example.com/"),
        tls_section=expired,
    )

    report = asyncio.run(investigate_link("https://example.com/"))

    assert report["checks"]["tls"]["status"] == "expired"
    assert report["risk_report"]["category"] == "HIGH"
    assert report["verdict"] == "High Risk"
    assert "expired" in {indicator["type"] for indicator in report["indicators"]}
    assert any(e["source"] == "TLS certificate" for e in report["evidence"])


def test_compromised_ca_is_high_risk_without_qualifying_ti_match(monkeypatch):
    # Spec: 9-10 without a qualifying TI match => High Risk (class is score+TI only).
    compromised = _tls_stub(
        status="compromised_ca",
        score=100,
        findings=[
            {
                "type": "compromised_ca",
                "severity": "critical",
                "evidence": "issued by a known compromised or distrusted CA",
                "detail": "Issuer matches 'DigiNotar'",
            }
        ],
    )
    compromised["compromised_ca"] = {"matched": True, "name": "DigiNotar", "reason": "stub"}
    _offline_patches(
        monkeypatch,
        resolved=True,
        dns_error=None,
        chain=_chain("https://example.com/"),
        tls_section=compromised,
    )

    report = asyncio.run(investigate_link("https://example.com/"))

    assert report["risk_report"]["category"] == "CRITICAL"
    assert report["verdict"] == "High Risk"
    assert report["risk_class"] == "High Risk"


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------

@pytest.fixture()
def client(tmp_path, monkeypatch):
    import app.database as database

    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "test.db"))
    init_db()
    from app.main import app

    with TestClient(app) as test_client:
        yield test_client


def test_api_rejects_metadata_endpoint(client):
    response = client.post("/api/investigate", json={"url": "http://169.254.169.254/latest/meta-data/"})

    assert response.status_code == 400
    assert "SSRF" in response.json()["detail"]


def test_api_rejects_invalid_url(client):
    response = client.post("/api/investigate", json={"url": "javascript:alert(1)"})
    assert response.status_code == 400
    assert "Invalid URL" in response.json()["detail"]


def test_api_requires_url_field(client):
    response = client.post("/api/investigate", json={})
    assert response.status_code == 422


def test_api_persists_report_for_the_dashboard(client, monkeypatch):
    async def fake_investigate(url):
        return {
            "investigation_type": "link",
            "verdict": "High Risk",
            "risk_score": 7.9,
            "checks": {"display_url": "http://sbi-kyc-verify.xyz/login",
                       "normalized_url": "http://sbi-kyc-verify.xyz/login"},
            "risk_report": {"score": 79, "category": "HIGH", "breakdown": {}},
            "url_analysis": [], "parsed": {}, "header_analysis": {},
            "attachment_analysis": [], "ioc_summary": {}, "threat_intel": {},
            "mitre_techniques": [], "ai_verdict": None,
        }

    import app.api.investigate as api_module

    monkeypatch.setattr(api_module, "investigate_link", fake_investigate)

    response = client.post("/api/investigate", json={"url": "http://sbi-kyc-verify.xyz/login"})
    assert response.status_code == 200
    investigation_id = response.json()["email_id"]

    listing = client.get("/api/analyses").json()
    assert any(row["email_id"] == investigation_id for row in listing)

    stored = client.get(f"/api/analyses/{investigation_id}").json()
    assert stored["verdict"] == "High Risk"


# --------------------------------------------------------------------------
# Website security assessment (Module 5)
# --------------------------------------------------------------------------

SIX_FIELDS = {
    "issue",
    "technical evidence",
    "potential impact",
    "severity",
    "recommended remediation",
    "relevant limitation",
}


def _chain_with_headers(url, headers, **overrides):
    chain = _chain(url, **overrides)
    chain["hops"][0]["headers"] = headers
    return chain


def _website_security(monkeypatch, *, chain, resolved=True, dns_error=None):
    _offline_patches(monkeypatch, resolved=resolved, dns_error=dns_error, chain=chain)
    report = asyncio.run(investigate_link(chain["hops"][0]["url"]))
    return report, report["checks"]["website_security"]


def test_header_findings_report_present_and_missing(monkeypatch):
    _, ws = _website_security(
        monkeypatch,
        chain=_chain_with_headers(
            "https://www.google.com/", {"strict-transport-security": "max-age=31536000"}
        ),
    )

    assert ws["status"] == "assessed"
    assert ws["headers_present"] == 1
    assert ws["summary"] == "1 of 6 security headers present"
    assert ws["headers"]["strict-transport-security"]["present"] is True

    missing = [f for f in ws["findings"] if f["issue"].startswith("Security header missing")]
    assert len(missing) == 5
    # A missing header is Low or Medium, never Critical / High on an HTTPS site.
    assert {f["severity"] for f in missing} <= {"Low", "Medium"}
    # Every finding carries all six required fields.
    for finding in ws["findings"]:
        assert SIX_FIELDS <= set(finding)
        assert all(str(finding[field]).strip() for field in SIX_FIELDS)


def test_missing_hsts_on_plain_http_is_high(monkeypatch):
    _, ws = _website_security(monkeypatch, chain=_chain_with_headers("http://neverssl.com/", {}))

    assert ws["status"] == "assessed"
    assert ws["http"]["plain_http"] is True
    assert ws["http"]["final_scheme"] == "http"

    hsts = next(f for f in ws["findings"] if f["issue"].endswith("STRICT-TRANSPORT-SECURITY"))
    assert hsts["severity"] == "High"

    http_finding = next(f for f in ws["findings"] if f["issue"] == "HTTP configuration assessed")
    assert http_finding["severity"] == "High"
    assert "plain HTTP" in http_finding["technical evidence"]
    assert "plain HTTP" in ws["summary"]


def test_http_to_https_redirect_is_low_and_recorded(monkeypatch):
    chain = _chain_with_headers("https://example.com/", {"strict-transport-security": "max-age=1"}, redirect_count=1)
    chain["hops"] = [
        {"hop": 1, "url": "http://example.com/", "status": 301, "location": "https://example.com/",
         "content_type": "text/html", "bytes_read": 0, "truncated": False, "title": None,
         "server": None, "headers": {}, "error": None},
        {"hop": 2, "url": "https://example.com/", "status": 200, "location": None,
         "content_type": "text/html", "bytes_read": 10, "truncated": False, "title": "Example",
         "server": None, "headers": {"strict-transport-security": "max-age=1"}, "error": None},
    ]
    _offline_patches(monkeypatch, resolved=True, dns_error=None, chain=chain)

    report = asyncio.run(investigate_link("http://example.com"))
    ws = report["checks"]["website_security"]

    assert ws["http"]["plain_http"] is False
    assert ws["http"]["redirects_to_https"] is True
    http_finding = next(f for f in ws["findings"] if f["issue"] == "HTTP configuration assessed")
    assert http_finding["severity"] == "Low"


def test_exposed_endpoint_is_a_high_finding_and_other_statuses_are_not(monkeypatch):
    _offline_patches(monkeypatch, resolved=True, dns_error=None, chain=_chain("https://ex.example/"))

    async def fake_probes(base_url, timeout=5, max_bytes=64 * 1024):
        return [
            {"path": "/.env", "url": "https://ex.example/.env", "status": 200, "exposed": True,
             "bytes_read": 42, "content_type": "text/plain", "error": None},
            {"path": "/.git/HEAD", "url": "https://ex.example/.git/HEAD", "status": 403,
             "exposed": False, "bytes_read": 0, "content_type": None, "error": None},
        ]

    monkeypatch.setattr(li, "probe_sensitive_paths", fake_probes)
    ws = asyncio.run(investigate_link("https://ex.example/"))["checks"]["website_security"]

    exposed = [f for f in ws["findings"] if f["issue"].startswith("Exposed sensitive endpoint")]
    assert len(exposed) == 1
    assert exposed[0]["issue"] == "Exposed sensitive endpoint: /.env"
    assert exposed[0]["severity"] == "High"
    assert "HTTP 200" in exposed[0]["technical evidence"]
    assert SIX_FIELDS <= set(exposed[0])

    not_exposed = {entry["path"]: entry for entry in ws["not_exposed"]}
    assert not_exposed["/.git/HEAD"]["status"] == 403
    assert not_exposed["/.git/HEAD"]["evidence"].startswith("HTTP 403")
    assert "exposed sensitive endpoint detected" in ws["summary"]


def test_unfetched_target_reports_website_checks_unavailable(monkeypatch):
    chain = _chain(
        "https://nx.example/",
        hops=[{"hop": 1, "url": "https://nx.example/", "status": None, "location": None,
               "content_type": None, "bytes_read": 0, "truncated": False, "title": None,
               "server": None, "headers": {}, "error": "hostname did not resolve"}],
        final_url="https://nx.example/",
        hop_count=1,
        error="did not resolve",
    )
    _, ws = _website_security(monkeypatch, chain=chain, resolved=False, dns_error="nxdomain")

    assert ws["status"] == "website checks unavailable"
    assert ws["findings"] == []
    assert "unavailable" in ws["summary"].lower()


def test_probe_only_requests_the_two_fixed_paths(monkeypatch):
    requested = []

    async def fake_validate(url, timeout=5):
        return {"allowed": True, "blocked": False, "resolved": True, "reason": "",
                "host": "ex.example", "ips": ["93.184.216.34"]}

    async def fake_safe_get(url, timeout, max_bytes, capture_prefix=False):
        requested.append(url)
        status = 200 if url.endswith("/.env") else 404
        return {"url": url, "status": status, "content_type": "text/plain", "location": None,
                "bytes_read": 12 if status == 200 else 0, "truncated": False, "title": None,
                "server": None, "headers": {}, "error": None,
                "body_prefix": "APP_ENV=production\nDB_PASSWORD=x" if status == 200 else ""}

    monkeypatch.setattr(ssrf_guard, "validate_target", fake_validate)
    monkeypatch.setattr(ssrf_guard, "_safe_get", fake_safe_get)

    results = asyncio.run(ssrf_guard.probe_sensitive_paths("https://ex.example/deep/path?q=1"))

    assert requested == ["https://ex.example/.env", "https://ex.example/.git/HEAD"]
    assert [r["path"] for r in results] == ["/.env", "/.git/HEAD"]
    assert results[0]["exposed"] is True
    assert results[0]["status"] == 200
    assert results[1]["exposed"] is False


def test_waf_style_200_html_page_is_not_reported_as_exposed(monkeypatch):
    """A bank WAF answering every path with 200 + 'Request Rejected' is not a leak."""

    async def fake_validate(url, timeout=5):
        return {"allowed": True, "blocked": False, "resolved": True, "reason": "",
                "host": "sbi.co.in", "ips": ["93.184.216.34"]}

    async def fake_safe_get(url, timeout, max_bytes, capture_prefix=False):
        body = (
            "<html><head><title>Request Rejected</title></head>"
            "<body>The requested URL was rejected.</body></html>"
        )
        return {"url": url, "status": 200, "content_type": "text/html; charset=utf-8",
                "location": None, "bytes_read": len(body), "truncated": False, "title": None,
                "server": None, "headers": {}, "error": None, "body_prefix": body}

    monkeypatch.setattr(ssrf_guard, "validate_target", fake_validate)
    monkeypatch.setattr(ssrf_guard, "_safe_get", fake_safe_get)

    results = asyncio.run(ssrf_guard.probe_sensitive_paths("https://sbi.co.in/"))

    assert [r["exposed"] for r in results] == [False, False]
    assert all(r["status"] == 200 for r in results)
    assert all("HTML page" in r["note"] for r in results)


def test_real_git_head_is_recognised_as_exposed(monkeypatch):
    async def fake_validate(url, timeout=5):
        return {"allowed": True, "blocked": False, "resolved": True, "reason": "",
                "host": "leaky.example", "ips": ["93.184.216.34"]}

    async def fake_safe_get(url, timeout, max_bytes, capture_prefix=False):
        body = "ref: refs/heads/main\n" if url.endswith("/.git/HEAD") else "SECRET_KEY=abc123\n"
        return {"url": url, "status": 200, "content_type": "text/plain", "location": None,
                "bytes_read": len(body), "truncated": False, "title": None,
                "server": None, "headers": {}, "error": None, "body_prefix": body}

    monkeypatch.setattr(ssrf_guard, "validate_target", fake_validate)
    monkeypatch.setattr(ssrf_guard, "_safe_get", fake_safe_get)

    results = asyncio.run(ssrf_guard.probe_sensitive_paths("https://leaky.example/"))

    assert [r["exposed"] for r in results] == [True, True]
