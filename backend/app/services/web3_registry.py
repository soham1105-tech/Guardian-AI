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
RECEIPT_TIMEOUT = 60
SEPOLIA_CHAIN_ID = 11155111


class RegistryUnavailable(RuntimeError):
    """The local chain or the deployment manifest is not available."""


def rpc_url() -> str:
    return os.getenv("WEB3_RPC_URL", DEFAULT_RPC_URL)


def _private_key() -> str | None:
    """Deployer key for signing (Sepolia/remote). Empty/unset => local unlocked account."""
    key = os.getenv("PRIVATE_KEY", "").strip()
    return key or None


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
            "--network localhost` (or --network sepolia) in blockchain/ first"
        )

    try:
        deployment = json.loads(CONTRACT_FILE.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise RegistryUnavailable(f"backend/contract.json is not valid JSON: {exc}")

    if not deployment.get("address") or not deployment.get("abi"):
        raise RegistryUnavailable("backend/contract.json has no address/abi")
    return deployment


def _connect():
    w3 = Web3(Web3.HTTPProvider(rpc_url(), request_kwargs={"timeout": 10}))
    try:
        connected = w3.is_connected()
    except Exception:
        connected = False

    if not connected:
        raise RegistryUnavailable(
            f"no Ethereum node reachable at {rpc_url()} - is the RPC URL correct and the node running?"
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


def _etherscan_url(chain_id, tx_hash_hex: str | None) -> str | None:
    if not tx_hash_hex or chain_id != SEPOLIA_CHAIN_ID:
        return None
    tx = tx_hash_hex if tx_hash_hex.startswith("0x") else "0x" + tx_hash_hex
    return f"https://sepolia.etherscan.io/tx/{tx}"


def _with_etherscan(result: dict, tx_hash_hex: str | None) -> dict:
    url = _etherscan_url(result.get("chain_id"), tx_hash_hex)
    if url:
        result["etherscan_url"] = url
    return result


def _send_submit(w3, contract, hash_bytes, verdict: str):
    """Send submitReport: signed tx when PRIVATE_KEY is set, else unlocked local account."""
    key = _private_key()
    if key:
        try:
            account = w3.eth.account.from_key(key)
        except Exception as exc:
            raise RegistryUnavailable(f"PRIVATE_KEY is invalid: {exc}")
        try:
            nonce = w3.eth.get_transaction_count(account.address)
            tx = contract.functions.submitReport(hash_bytes, verdict).build_transaction(
                {
                    "from": account.address,
                    "nonce": nonce,
                    "chainId": int(w3.eth.chain_id),
                }
            )
            # Let the node/provider estimate gas; fill missing fields defensively.
            if "gas" not in tx:
                tx["gas"] = w3.eth.estimate_gas(tx)
            if "gasPrice" not in tx and "maxFeePerGas" not in tx:
                try:
                    tx["maxFeePerGas"] = w3.eth.gas_price
                    tx["maxPriorityFeePerGas"] = min(w3.eth.gas_price // 10, w3.to_wei(2, "gwei"))
                    tx.pop("gasPrice", None)
                except Exception:
                    tx["gasPrice"] = w3.eth.gas_price
            signed = w3.eth.account.sign_transaction(tx, private_key=key)
            raw = getattr(signed, "raw_transaction", None) or getattr(signed, "rawTransaction", None)
            tx_hash = w3.eth.send_raw_transaction(raw)
            return tx_hash
        except RegistryUnavailable:
            raise
        except Exception as exc:
            raise RegistryUnavailable(f"submitting the signed report hash failed: {exc}")

    sender = _accounts(w3)
    try:
        return contract.functions.submitReport(hash_bytes, verdict).transact({"from": sender})
    except Exception as exc:
        raise RegistryUnavailable(f"submitting the report hash failed: {exc}")


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
        result = {
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
        return result

    try:
        tx_hash = _send_submit(w3, contract, hash_bytes, verdict)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=RECEIPT_TIMEOUT)
    except RegistryUnavailable:
        raise
    except Exception as exc:
        raise RegistryUnavailable(f"submitting the report hash failed: {exc}")

    if receipt.get("status") != 1:
        raise RegistryUnavailable("the registry transaction was reverted")

    stored = contract.functions.verifyReport(hash_bytes).call()
    tx_hex = tx_hash.hex() if hasattr(tx_hash, "hex") else str(tx_hash)
    if not tx_hex.startswith("0x"):
        tx_hex = "0x" + tx_hex

    result = {
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
    return _with_etherscan(result, tx_hex)
