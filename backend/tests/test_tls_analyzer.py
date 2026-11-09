"""Offline tests for the TLS certificate analyzer (Module 2).

Certificates are generated locally with ``cryptography`` — no network access is
needed for the scoring rules, and the error paths are exercised with stubs.
"""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.services import tls_analyzer as tls

NOW = datetime.now(timezone.utc)


def _make_certificate(
    host="example.com",
    *,
    issuer_org="Let's Encrypt",
    self_signed=False,
    not_before=None,
    not_after=None,
    san=None,
):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    issuer = (
        subject
        if self_signed
        else x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_org),
                x509.NameAttribute(NameOID.COMMON_NAME, f"{issuer_org} CA"),
            ]
        )
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or NOW - timedelta(days=1))
        .not_valid_after(not_after or NOW + timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(name) for name in (san or [host])]
            ),
            critical=False,
        )
        .sign(key if self_signed else ec.generate_private_key(ec.SECP256R1()), hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _analyze(der, host="example.com", *, trusted=True, error=None):
    return tls.summarize_certificate(
        host, der, chain_trusted=trusted, verify_error=error, protocol="TLSv1.3"
    )


# ---------------------------------------------------------------------------
# Scoring rules
# ---------------------------------------------------------------------------

def test_valid_certificate_from_trusted_ca_has_no_penalty():
    section = _analyze(_make_certificate())

    assert section["status"] == "valid"
    assert section["score"] == 0
    assert section["findings"] == []
    assert section["hostname"]["matches"] is True
    assert section["hostname"]["matched_value"] == "example.com"
    assert section["certificate"]["expired"] is False
    assert section["certificate"]["self_signed"] is False
    assert section["certificate"]["public_key_type"].startswith("EC")
    assert section["certificate"]["public_key_bits"] == 256


def test_valid_certificate_always_carries_the_disclaimer():
    assert _analyze(_make_certificate())["note"] == "A valid certificate does not mean the website is safe"


def test_expired_certificate_is_high_risk_evidence():
    der = _make_certificate(
        not_before=NOW - timedelta(days=400), not_after=NOW - timedelta(days=10)
    )
    section = _analyze(der, trusted=False, error="certificate has expired")

    assert section["status"] == "expired"
    assert 60 <= section["score"] < 80  # HIGH, not CRITICAL
    kinds = {finding["type"] for finding in section["findings"]}
    assert "expired" in kinds
    assert section["certificate"]["days_remaining"] is None
    assert "expired" in " ".join(f["evidence"] for f in section["findings"]).lower()


def test_not_yet_valid_certificate_is_flagged():
    der = _make_certificate(
        not_before=NOW + timedelta(days=5), not_after=NOW + timedelta(days=95)
    )
    section = _analyze(der, trusted=False, error="certificate is not yet valid")

    assert section["status"] == "not_yet_valid"
    assert any(finding["type"] == "not_yet_valid" for finding in section["findings"])


def test_hostname_mismatch_is_flagged_against_the_san():
    der = _make_certificate(host="other.example", san=["other.example"])
    section = _analyze(der, trusted=False, error="Hostname mismatch")

    assert section["status"] == "hostname_mismatch"
    assert section["hostname"]["matches"] is False
    mismatch = next(f for f in section["findings"] if f["type"] == "hostname_mismatch")
    assert "example.com" in mismatch["evidence"]


def test_wildcard_san_matches_exactly_one_label():
    der = _make_certificate(host="*.example.com", san=["*.example.com"])

    assert tls.hostname_matches("www.example.com", x509.load_der_x509_certificate(der))[0] is True
    assert tls.hostname_matches("a.b.example.com", x509.load_der_x509_certificate(der))[0] is False


def test_self_signed_certificate_is_flagged():
    der = _make_certificate(self_signed=True)
    section = _analyze(der, trusted=False, error="self-signed certificate")

    assert section["status"] == "self_signed"
    assert section["certificate"]["self_signed"] is True
    assert 60 <= section["score"] < 80
    assert any(finding["type"] == "self_signed" for finding in section["findings"])


@pytest.mark.parametrize("ca_name", ["DigiNotar", "eMudhra", "Symantec"])
def test_compromised_ca_from_json_is_critical(ca_name):
    der = _make_certificate(issuer_org=ca_name)
    section = _analyze(der, trusted=False, error="unable to get local issuer certificate")

    assert section["status"] == "compromised_ca"
    assert section["score"] == tls.TLS_COMPROMISED_CA_SCORE
    assert section["compromised_ca"]["matched"] is True
    assert section["compromised_ca"]["name"] == ca_name
    assert any(
        finding["evidence"] == "issued by a known compromised or distrusted CA"
        for finding in section["findings"]
    )


def test_compromised_ca_outranks_other_tls_defects():
    der = _make_certificate(
        issuer_org="DigiNotar",
        not_after=NOW - timedelta(days=1),
        not_before=NOW - timedelta(days=300),
    )
    section = _analyze(der, trusted=False, error="certificate has expired")

    assert section["status"] == "compromised_ca"
    assert section["score"] == 100


def test_untrusted_chain_alone_is_flagged():
    der = _make_certificate(issuer_org="Acme Internal CA")
    section = _analyze(der, trusted=False, error="unable to get local issuer certificate")

    assert section["status"] == "untrusted_chain"
    assert 60 <= section["score"] < 80


# ---------------------------------------------------------------------------
# Certificate Transparency
# ---------------------------------------------------------------------------

def test_ct_recently_issued_certificates_are_flagged():
    now = datetime.now(timezone.utc)
    rows = [
        {"id": 1, "not_before": (now - timedelta(days=2)).isoformat(), "common_name": "a.example",
         "issuer_name": "Test CA"},
        {"id": 2, "not_before": (now - timedelta(days=3)).isoformat(), "common_name": "b.example",
         "issuer_name": "Other CA"},
        {"id": 3, "not_before": (now - timedelta(days=200)).isoformat(), "common_name": "old.example",
         "issuer_name": "Test CA"},
    ]
    summary = tls.summarize_ct_rows(rows, "example.com")

    assert summary["available"] is True
    assert summary["certificate_count"] == 3
    assert summary["recently_issued_count"] == 2
    assert summary["recently_issued"][0]["common_name"] in {"a.example", "b.example"}
    assert summary["window_days"] == 7


def test_ct_deduplicates_and_marks_truncation():
    now = datetime.now(timezone.utc)
    rows = [
        {"id": 1, "not_before": now.isoformat(), "common_name": "a.example"},
        {"id": 1, "not_before": now.isoformat(), "common_name": "a.example"},
    ]
    summary = tls.summarize_ct_rows(rows, "example.com", truncated=True)

    assert summary["certificate_count"] == 1
    assert summary["truncated"] is True
    assert summary["count_note"].startswith("at least 1")


def test_ct_truncated_json_keeps_complete_objects():
    payload = '[{"id": 1, "not_before": "2026-01-01T00:00:00"}, {"id": 2, "not_b'
    rows, truncated = tls._parse_ct_payload(payload)

    assert truncated is True
    assert len(rows) == 1
    assert rows[0]["id"] == 1


def test_ct_unavailable_is_reported_not_raised():
    result = asyncio.run(
        tls.check_ct_log("example.com", endpoint="http://127.0.0.1:1", timeout=1)
    )

    assert result["available"] is False
    assert result["error"].startswith("CT log unavailable")


# ---------------------------------------------------------------------------
# Network-free section paths
# ---------------------------------------------------------------------------

def test_plain_http_records_no_tls_as_evidence():
    section = asyncio.run(tls.analyze_tls("http://example.com/", "example.com", scheme="http"))

    assert section["status"] == "no_tls"
    assert section["analyzed"] is False
    assert section["https"] is False
    assert section["score"] == 0
    assert section["note"] == "A valid certificate does not mean the website is safe"
    assert section["findings"][0]["evidence"].startswith("no TLS (plain HTTP)")
    assert section["certificate"] is None


def test_unresolvable_host_records_evidence(monkeypatch):
    async def no_addresses(host, timeout=5):
        return []

    monkeypatch.setattr(tls, "resolve_host", no_addresses)
    section = asyncio.run(tls.analyze_tls("https://nope.invalid/", "nope.invalid"))

    assert section["status"] == "unreachable"
    assert section["findings"][0]["type"] == "unreachable"
    assert "did not resolve" in section["findings"][0]["evidence"]


def test_host_resolving_to_private_ip_is_refused(monkeypatch):
    async def loopback(host, timeout=5):
        return ["127.0.0.1"]

    monkeypatch.setattr(tls, "resolve_host", loopback)
    section = asyncio.run(tls.analyze_tls("https://internal.example/", "internal.example"))

    assert section["status"] == "blocked"
    assert section["findings"][0]["type"] == "blocked"


def test_handshake_failure_never_raises(monkeypatch):
    async def public(host, timeout=5):
        return ["93.184.216.34"]

    def boom(host, address, port, timeout):
        raise OSError("connection refused")

    monkeypatch.setattr(tls, "resolve_host", public)
    monkeypatch.setattr(tls, "_fetch_leaf_blocking", boom)
    section = asyncio.run(tls.analyze_tls("https://example.com/", "example.com"))

    assert section["analyzed"] is False
    assert section["status"] == "unreachable"
    assert "TLS connection failed" in section["error"]
    assert section["findings"][0]["type"] == "unreachable"
