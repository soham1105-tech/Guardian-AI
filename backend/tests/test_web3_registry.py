"""Module 6 - on-chain ThreatRegistry.

The chain itself is faked here so the suite stays hermetic; the live-chain
behaviour is exercised by the deployment/verification steps in the README.
"""

import json

import pytest
from fastapi.testclient import TestClient

from app.database import init_db
from app.services import web3_registry
from app.services.reports_store import record_report
from app.services.web3_registry import (
    RegistryUnavailable,
    canonical_json,
    register_hash,
    report_hash,
    verify_hash,
)

ADDRESS = "0x5FbDB2315678afecb367f032d93F642f64180aa3"


# --------------------------------------------------------------------------
# Canonical hashing
# --------------------------------------------------------------------------

def test_canonical_json_ignores_key_order_and_whitespace():
    a = {"b": 1, "a": {"y": [1, 2], "x": "sbi"}}
    b = {"a": {"x": "sbi", "y": [1, 2]}, "b": 1}

    assert canonical_json(a) == canonical_json(b)
    assert " " not in canonical_json(a)
    assert canonical_json(a).startswith('{"a":')


def test_report_hash_is_a_bytes32_hex_digest():
    value = report_hash({"risk_class": "High Risk", "url": "http://sbi-kyc-verify.xyz/login"})

    assert value.startswith("0x")
    assert len(value) == 66
    int(value, 16)  # valid hex


def test_report_hash_changes_when_the_report_changes():
    base = {"risk_class": "High Risk", "score": 79}
    assert report_hash(base) == report_hash(dict(base))
    assert report_hash(base) != report_hash({**base, "score": 80})


def test_report_hash_is_stable_for_unicode_content():
    report = {"text": "Dear customer — your SBI account", "risk_class": "Suspicious"}
    assert report_hash(report) == report_hash(json.loads(json.dumps(report, ensure_ascii=False)))


# --------------------------------------------------------------------------
# Service behaviour against a faked chain
# --------------------------------------------------------------------------

class _Call:
    def __init__(self, fn):
        self._fn = fn

    def call(self):
        return self._fn()


class _Functions:
    def __init__(self, store, tx_hash="0x" + "ab" * 32):
        self.store = store
        self.tx_hash = tx_hash
        self.transacts = 0

    def verifyReport(self, hash_bytes):
        key = hash_bytes.hex()
        entry = self.store.get(key)
        if entry is None:
            return _Call(lambda: (False, 0, "0x" + "00" * 20, ""))
        return _Call(lambda: (True, entry["timestamp"], entry["submitter"], entry["verdict"]))

    def submitReport(self, hash_bytes, verdict):
        def _transact(tx):
            self.transacts += 1
            self.store[hash_bytes.hex()] = {
                "timestamp": 1793000000,
                "submitter": tx["from"],
                "verdict": verdict,
            }
            return self.tx_hash

        return type("_T", (), {"transact": staticmethod(_transact)})()


class _FakeEth:
    accounts = ["0x" + "11" * 20]

    def wait_for_transaction_receipt(self, tx_hash, timeout=30):
        return {"status": 1, "transactionHash": tx_hash}


class _FakeW3:
    eth = _FakeEth()


def _fake_chain(monkeypatch, store=None):
    store = store if store is not None else {}
    functions = _Functions(store)
    contract = type("C", (), {"functions": functions})()

    monkeypatch.setattr(web3_registry, "load_deployment",
                        lambda: {"address": ADDRESS, "abi": [], "chain_id": 31337})
    monkeypatch.setattr(web3_registry, "_connect", lambda: _FakeW3())
    monkeypatch.setattr(web3_registry, "_contract", lambda w3, dep: contract)
    # Hermetic tests use the faked unlocked-account path (not a real PRIVATE_KEY from env).
    monkeypatch.setattr(web3_registry, "_private_key", lambda: None)
    return functions


def test_verify_returns_exists_false_for_an_unknown_hash(monkeypatch):
    _fake_chain(monkeypatch)

    result = verify_hash(report_hash({"nothing": "registered"}))

    assert result["exists"] is False
    assert result["timestamp"] is None
    assert result["verdict"] is None
    assert result["contract_address"] == ADDRESS


def test_register_then_verify(monkeypatch):
    _fake_chain(monkeypatch)
    hex_hash = report_hash({"risk_class": "High Risk"})

    registered = register_hash(hex_hash, "High Risk")
    assert registered["tx_hash"] == "0x" + "ab" * 32
    assert registered["contract_address"] == ADDRESS
    assert registered["exists"] is True
    assert registered["already_registered"] is False

    verified = verify_hash(hex_hash)
    assert verified["exists"] is True
    assert verified["verdict"] == "High Risk"
    assert verified["timestamp"] == 1793000000
    assert verified["submitter"] == _FakeEth.accounts[0]


def test_registering_twice_does_not_resubmit(monkeypatch):
    functions = _fake_chain(monkeypatch)
    hex_hash = report_hash({"risk_class": "Suspicious"})

    first = register_hash(hex_hash, "Suspicious")
    second = register_hash(hex_hash, "Suspicious")

    assert first["already_registered"] is False
    assert second["already_registered"] is True
    assert second["tx_hash"] is None
    assert functions.transacts == 1


def test_missing_deployment_manifest_is_an_error_not_a_fake_verification(monkeypatch, tmp_path):
    monkeypatch.setattr(web3_registry, "CONTRACT_FILE", tmp_path / "absent.json")

    with pytest.raises(RegistryUnavailable):
        verify_hash("0x" + "00" * 32)


# --------------------------------------------------------------------------
# HTTP endpoints
# --------------------------------------------------------------------------

@pytest.fixture()
def client(tmp_path, monkeypatch):
    import app.database as database

    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "test.db"))
    init_db()
    from app.main import app

    with TestClient(app) as test_client:
        yield test_client


def _store_report(report_id, report):
    record_report(
        report_id=report_id,
        input_type="url",
        input_text="http://sbi-kyc-verify.xyz/login",
        domain="sbi-kyc-verify.xyz",
        brand="sbi",
        risk_class=report.get("risk_class"),
        risk_score=7.9,
        indicators=[],
        report=report,
    )


def test_api_reports_unknown_id_is_404(client):
    assert client.post("/api/reports/nope/register").status_code == 404
    assert client.get("/api/reports/nope/verify").status_code == 404


def test_api_register_and_verify(client, monkeypatch):
    _fake_chain(monkeypatch)
    _store_report("r1", {"risk_class": "High Risk", "report": "material"})

    registered = client.post("/api/reports/r1/register")
    assert registered.status_code == 200
    body = registered.json()
    assert body["tx_hash"] == "0x" + "ab" * 32
    assert body["contract_address"] == ADDRESS
    assert body["report_hash"].startswith("0x")

    verified = client.get("/api/reports/r1/verify")
    assert verified.status_code == 200
    assert verified.json()["exists"] is True
    assert verified.json()["verdict"] == "High Risk"


def test_api_verify_for_unregistered_report_is_false(client, monkeypatch):
    _fake_chain(monkeypatch)
    _store_report("r2", {"risk_class": "High Risk", "report": "never registered"})

    verified = client.get("/api/reports/r2/verify")

    assert verified.status_code == 200
    assert verified.json()["exists"] is False


def test_api_returns_503_when_the_chain_is_unavailable(client, monkeypatch, tmp_path):
    monkeypatch.setattr(web3_registry, "CONTRACT_FILE", tmp_path / "absent.json")
    _store_report("r3", {"risk_class": "High Risk"})

    response = client.post("/api/reports/r3/register")
    assert response.status_code == 503
    assert "contract.json" in response.json()["detail"]


def test_hash_is_taken_from_the_stored_json_not_the_decorated_view(client, monkeypatch):
    """A report served with recomputed related_reports still verifies."""
    _fake_chain(monkeypatch)
    stored = {"risk_class": "High Risk", "checks": {"registered_domain": "sbi-kyc-verify.xyz"}}
    _store_report("r4", stored)

    expected = report_hash(stored)
    body = client.get("/api/reports/r4/verify").json()

    assert body["report_hash"] == expected
