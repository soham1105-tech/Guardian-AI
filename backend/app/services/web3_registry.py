"""On-chain report integrity registry (Module 6).

Only two things ever leave this module for the chain: the SHA-256 hash of a
report's canonical JSON and its verdict string (the risk class). URLs, email
bodies, phone numbers and every other piece of personal data stay off-chain.

The contract address and ABI are read from ``backend/contract.json``, which
``blockchain/scripts/deploy.js`` writes on every deployment - a fresh
``npx hardhat node`` resets the chain and changes the address, so it is never
hardcoded here.
"""

import hashlib
import json
import os
from pathlib import Path

from web3 import Web3

DEFAULT_RPC_URL = "http://127.0.0.1:8545"
CONTRACT_FILE = Path(__file__).resolve().parents[2] / "contract.json"
RECEIPT_TIMEOUT = 30


class RegistryUnavailable(RuntimeError):
    """The local chain or the deployment manifest is not available."""


def rpc_url() -> str:
    return os.getenv("WEB3_RPC_URL", DEFAULT_RPC_URL)


def canonical_json(report: dict) -> str:
    """Canonical form: sorted keys, no whitespace, UTF-8 safe."""
    return json.dumps(
        report or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )


def report_hash(report: dict) -> str:
    """SHA-256 of the canonical JSON, as a 0x-prefixed bytes32 hex string."""
    digest = hashlib.sha256(canonical_json(report).encode("utf-8")).hexdigest()
    return "0x" + digest


def load_deployment() -> dict:
    if not CONTRACT_FILE.exists():
        raise RegistryUnavailable(
            "backend/contract.json is missing - run `npx hardhat run scripts/deploy.js "
            "--network localhost` in blockchain/ first"
        )

    try:
        deployment = json.loads(CONTRACT_FILE.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise RegistryUnavailable(f"backend/contract.json is not valid JSON: {exc}")

    if not deployment.get("address") or not deployment.get("abi"):
        raise RegistryUnavailable("backend/contract.json has no address/abi")
    return deployment


def _connect():
    w3 = Web3(Web3.HTTPProvider(rpc_url(), request_kwargs={"timeout": 5}))
    try:
        connected = w3.is_connected()
    except Exception:
        connected = False

    if not connected:
        raise RegistryUnavailable(
            f"no Ethereum node reachable at {rpc_url()} - is `npx hardhat node` running?"
        )
    return w3


def _contract(w3, deployment):
    address = Web3.to_checksum_address(deployment["address"])
    return w3.eth.contract(address=address, abi=deployment["abi"])


def _accounts(w3):
    accounts = list(w3.eth.accounts)
    if not accounts:
        raise RegistryUnavailable("the node exposes no unlocked accounts to submit from")
    return accounts[0]


def verify_hash(hex_hash: str) -> dict:
    """Reads the registry for one hash. Never invents a result."""
    deployment = load_deployment()
    w3 = _connect()
    contract = _contract(w3, deployment)

    exists, timestamp, submitter, verdict = contract.functions.verifyReport(
        bytes.fromhex(hex_hash[2:])
    ).call()

    return {
        "report_hash": hex_hash,
        "contract_address": deployment["address"],
        "chain_id": deployment.get("chain_id"),
        "exists": bool(exists),
        "timestamp": int(timestamp) if exists else None,
        "submitter": submitter if exists else None,
        "verdict": verdict if exists else None,
    }


def register_hash(hex_hash: str, verdict: str) -> dict:
    """
    Submits the hash + verdict. If the hash is already on-chain it is reported
    as such instead of being re-submitted (the contract reverts on duplicates).
    """
    deployment = load_deployment()
    w3 = _connect()
    contract = _contract(w3, deployment)

    hash_bytes = bytes.fromhex(hex_hash[2:])
    existing = contract.functions.verifyReport(hash_bytes).call()

    if existing[0]:
        return {
            "report_hash": hex_hash,
            "contract_address": deployment["address"],
            "chain_id": deployment.get("chain_id"),
            "tx_hash": None,
            "already_registered": True,
            "exists": True,
            "timestamp": int(existing[1]),
            "submitter": existing[2],
            "verdict": existing[3],
        }

    sender = _accounts(w3)

    try:
        tx_hash = contract.functions.submitReport(hash_bytes, verdict).transact(
            {"from": sender}
        )
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=RECEIPT_TIMEOUT)
    except Exception as exc:
        raise RegistryUnavailable(f"submitting the report hash failed: {exc}")

    if receipt.get("status") != 1:
        raise RegistryUnavailable("the registry transaction was reverted")

    stored = contract.functions.verifyReport(hash_bytes).call()
    tx_hex = tx_hash.hex() if hasattr(tx_hash, "hex") else str(tx_hash)
    if not tx_hex.startswith("0x"):
        tx_hex = "0x" + tx_hex

    return {
        "report_hash": hex_hash,
        "contract_address": deployment["address"],
        "chain_id": deployment.get("chain_id"),
        "tx_hash": tx_hex,
        "already_registered": False,
        "exists": bool(stored[0]),
        "timestamp": int(stored[1]) if stored[0] else None,
        "submitter": stored[2] if stored[0] else None,
        "verdict": stored[3] if stored[0] else verdict,
    }
