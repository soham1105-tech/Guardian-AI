# Guardian.AI — Testing Report (Prompt 7)

Environment: local workspace `D:\hackmatrix\guardian-ai` (repo folder as checked out). Backend on `http://127.0.0.1:8000` (uvicorn, restarted to load fresh `backend/contract.json`), frontend built with Vite, Hardhat local node on `http://127.0.0.1:8545` with `ThreatRegistry` deployed.

All `risk_class` values observed across the six cases and the on-chain verify verdict are in the allowed set: **Low Risk / Suspicious / High Risk / Confirmed Malicious / Inconclusive**.

## Six required test cases

| # | Case | Input | Expected | Actual result | `risk_class` |
|---|------|-------|----------|---------------|--------------|
| 1 | Suspicious (phishing URL) | `POST /api/investigate` `{"url":"https://testsafebrowsing.appspot.com/s/phishing.html"}` | High Risk or Confirmed Malicious | **PASS** — `risk_score=6.9` | `High Risk` |
| 2 | Suspicious (homograph) | `POST /api/investigate` `{"url":"https://аpple.com"}` (Cyrillic `а` U+0430) | Flagged, homograph indicator present | **PASS** — `risk_score=5.8`, homograph/punycode/confusable indicator present in report (`has_homograph=True`) | `High Risk` |
| 3 | Suspicious (fake SBI KYC SMS) | `POST /api/analyze-message` `{"text":"Dear customer, your SBI account will be blocked today. Verify KYC now at http://sbi-kyc-verify.xyz/login"}` | High Risk or Confirmed Malicious | **PASS** — `risk_score=7.9` | `High Risk` |
| 4 | Benign | `POST /api/investigate` `{"url":"https://www.google.com"}` | Low Risk | **PASS** — `risk_score=0.0` | `Low Risk` |
| 5 | Benign | `POST /api/investigate` `{"url":"https://www.github.com"}` | Low Risk | **PASS** — `risk_score=0.0` | `Low Risk` |
| 6 | Benign (real bank, no false positive) | `POST /api/investigate` `{"url":"https://www.sbi.co.in"}` | Low Risk | **PASS** — `risk_score=0.0` | `Low Risk` |

## Automated tests

- **Backend pytest** (from `backend/`, `.venv`): `python -m pytest tests/ -q` → **98 passed, 24 warnings in 16.55s** (exit 0). Warnings are pre-existing deprecations (`starlette.testclient`/httpx, `datetime.utcnow()` in existing modules, FastAPI `on_event`) — no verdict/risk logic changed, no suppressions added.
- **Frontend build** (from `frontend/`): `npm run build` → **success** (`vite v8.2.2`, 97 modules, `dist/assets/index-Cuo97JMy.js` 343.79 kB gzip 106.99 kB, built in ~279ms).

## Endpoint status (one line each)

| Endpoint | Method | Status | Notes |
|----------|--------|--------|-------|
| `/api/investigate` | POST | **OK** | Returns report with `risk_class` in allowed set; verified on cases 1,2,4,5,6. |
| `/api/analyze-message` | POST | **OK** | Verified on fake SBI KYC SMS (case 3). |
| `/api/upload` (email `.eml`) | POST | **OK (code path preserved; exercised in prior prompts)** | `.eml` flow unchanged by Prompt 7; not re-uploaded in this run. |
| `/api/reports` (reports list) | GET | **OK (registered router; exercised via app/tests)** | Backend reports router active; list/detail exercised in prior runs. |
| `/api/reports/{id}/register` | POST | **OK** | Anchored report `8f410c34-9919-4473-8018-95549c586022`; returned `tx_hash`, `contract_address`, `report_hash`. |
| `/api/reports/{id}/verify` | GET | **OK** | `exists=True`, `verdict="Low Risk"`, timestamp/submitter returned for the registered report. |

## Web3 verification evidence (this run)

- **Contract address:** `0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9` (chain 31337, localhost; redeployed to fresh `npx hardhat node` — address written to `backend/contract.json`)
- **Report registered:** `8f410c34-9919-4473-8018-95549c586022` (Low Risk, github.com)
- **Transaction hash:** `0xa715dd711eebe9702163db7fd2f4e884cb9628427ce57bb498dc1159a205bd6a`
- **Report hash:** `0xee81b1d419c0bbdd0a535dcb07b28e62ecd4c02b95651b85581b6bf080488f1f`
- **Verify:** `exists=True`, `timestamp=1794203618`, `submitter=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`, `verdict="Low Risk"`

> Local Hardhat chain is ephemeral; a restarted node invalidates prior on-chain state. Keep the node running for demos and record the tx hash/address you show.

## Risk-class audit

Allowed values (only): `Low Risk`, `Suspicious`, `High Risk`, `Confirmed Malicious`, `Inconclusive`. Observed across `/api/investigate`, `/api/analyze-message`, and on-chain verify verdict in this run: **Low Risk, High Risk** only. No out-of-spec values (e.g. `SAFE`, `HIGH`, `SUSPICIOUS`) observed; no mapping changes required.
