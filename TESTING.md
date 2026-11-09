# Guardian.AI — Testing Report

Verified: 2026-11-09 (local). Commands run in `cmd`/bash from the repo root unless noted. The backend was started with `CORS_ORIGINS="http://localhost:5173,http://127.0.0.1:5173,http://localhost:5174,http://127.0.0.1:5174"` and `WEB3_RPC_URL="http://127.0.0.1:8545"` for API/on-chain checks.

## Six test cases

| # | Case | Exact input | Expected | Actual |
|---|---|---|---|---|
| 1 | Suspicious link (Google Safe Browsing test page) | `POST /api/investigate` `{"url":"https://testsafebrowsing.appspot.com/s/phishing.html"}` | High Risk or Confirmed Malicious | **PASS** — `risk_class=Confirmed Malicious`, `verdict=Confirmed Malicious`, `risk_score=10.0` |
| 2 | Suspicious link (IDN homograph, Cyrillic `а` U+0430) | `POST /api/investigate` `{"url":"https://аpple.com"}` (first `a` is Cyrillic) | Flagged; homograph indicator present | **PASS** — `risk_class=Confirmed Malicious`, `verdict=Confirmed Malicious`, `risk_score=10.0`; homograph indicator present (`type=homograph`, `value=xn--pple-43d.com`, detail notes non-ASCII look-alike `а` / punycode / IDN spoofing) |
| 3 | Suspicious bank SMS (fake SBI KYC) | `POST /api/analyze-message` `{"text":"Dear customer, your SBI account will be blocked today. Verify KYC now at http://sbi-kyc-verify.xyz/login"}` | High Risk or Confirmed Malicious | **PASS** — `risk_class=High Risk`, `verdict=High Risk`, `risk_score=7.9` |
| 4 | Benign | `POST /api/investigate` `{"url":"https://www.google.com"}` | Low Risk | **PASS** — `risk_class=Low Risk`, `verdict=Low Risk`, `risk_score=0.0`. Note (Prompt 8b): a live single-vendor reputation flag (e.g. VT 1/92) is recorded as an informational note (“1 vendor flagged…, below the evidence threshold of 2 — not counted toward the score”) and does **not** count as evidence or trigger Confirmed Malicious. |
| 5 | Benign | `POST /api/investigate` `{"url":"https://www.github.com"}` | Low Risk | **PASS** — `risk_class=Low Risk`, `verdict=Low Risk`, `risk_score=0.0` |
| 6 | Benign (real bank, no false positive) | `POST /api/investigate` `{"url":"https://www.sbi.co.in"}` | Low Risk | **PASS** — `risk_class=Low Risk`, `verdict=Low Risk`, `risk_score=0.0` |

## Automated tests

- **Backend (pytest):** `cd backend && python -m pytest tests/ -q` → **`108 passed, 28 warnings in 20.11s`** (full suite green; was 98 before Prompt 8b). Warnings are pre-existing deprecations (`httpx` testclient, `datetime.utcnow`, FastAPI `on_event`), not test failures.
- **Frontend (Vite build):** `cd frontend && npm run build` → **success** (`vite v8.2.2`, 97 modules transformed, `dist/assets/index-*.js` ~344 kB gzip ~107 kB, built in ~276 ms).

## Endpoint status (verified)

| Endpoint | Method | Status | Notes |
|---|---|---|---|
| `/api/investigate` | POST | **OK** | Link/domain investigation; returns report with `risk_class`/`verdict`/`risk_score` (0–10) and `checks` (cases 1,2,4,5,6). |
| `/api/analyze-message` | POST | **OK** | SMS/text/WhatsApp-style message analysis (case 3). |
| `/api/upload` | POST | **OK (implemented)** | `.eml` upload; exercised in the existing .eml flow/UI (not re-curl’d here to avoid mutating fixtures). |
| `/api/analyze/{email_id}` | POST | **OK (implemented)** | Email analysis; part of the .eml flow. |
| `/api/reports` | GET | **OK (implemented)** | Reports/investigations list (powers dashboard history). |
| `/api/reports/{report_id}` | GET | **OK (implemented)** | Single report. |
| `/api/reports/{report_id}/register` | POST | **OK** | On-chain registration (local Hardhat). Registered report `3d7fecbc-8837-452b-a085-7696b247231c` → `tx_hash=0x781240ba01ff5b134e2de6e32a876309f2591debd37817a84627e7a0d6657749`, `contract=0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9`, `chain_id=31337`, `exists=true`, `verdict=Confirmed Malicious`. |
| `/api/reports/{report_id}/verify` | GET | **OK** | Integrity/registry verification → `exists=true`, same hash/contract/submitter/verdict/timestamp. |

## Risk-class audit

Allowed values only: **Low Risk, Suspicious, High Risk, Confirmed Malicious, Inconclusive**. Across the six cases above: `Low Risk` (google, github, sbi.co.in), `High Risk` (SBI KYC SMS), `Confirmed Malicious` (phishing test, homograph). Class is determined by score + qualifying threat-intel match (Prompt 8b); no `SAFE/HIGH/SUSPICIOUS/CRITICAL` user-facing risk-class values observed.

## Caveats

- Live threat-intel/network results can vary by provider availability and time; Prompt 8b ensures a single-vendor flag is informational and cannot produce a false Confirmed Malicious.
- On-chain register/verify above used the **local Hardhat** chain (31337). A manual Sepolia deployment (real contract address + Etherscan tx) is a user action — see README and `DEPLOY.md`.
- Browser console/network visual checks (zero errors, empty/loading/error states) were not captured as screenshots in this run; the UI includes busy/disabled submit states and error messaging — verify in a browser with backend+frontend+Hardhat running before demo/submission.
