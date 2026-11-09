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
- On-chain register/verify was first proven on the local Hardhat chain (31337); Sepolia is now live (see below) and the hosted backend registers on Sepolia.
- Browser console/network visual checks (zero errors, empty/loading/error states) were not captured as screenshots in this run; the UI includes busy/disabled submit states and error messaging — verify in a browser with backend+frontend+Hardhat running before demo/submission.

- Sepolia verified live (Prompt 9b): deployment tx `0x5c98491f51012dc81bad0c012303c90f6d01406ec46d1df3203de69ece6a94c0` (https://sepolia.etherscan.io/tx/0x5c98491f51012dc81bad0c012303c90f6d01406ec46d1df3203de69ece6a94c0); register tx `0x9f592ba27b26ce990bc47ff3f0a5032b158dcb249b98b0ab8aceb50f8c2e4f2e` (https://sepolia.etherscan.io/tx/0x9f592ba27b26ce990bc47ff3f0a5032b158dcb249b98b0ab8aceb50f8c2e4f2e). Contract `0x8d752efC39D306FDF6482CA7686280704A1D480C`, `chain_id` 11155111, register returned `tx_hash`/`etherscan_url`, `exists=true`.


## Hosted verification (live)

_Run: 2026-11-09 (evening, UTC log). Target: `https://guardian-ai-backend-sqgq.onrender.com` (live on Render). Warmed with `GET /` → 200 before tests. Results are real API responses; verdicts/risk classes reflect live system behavior at test time._

| # | Case | Endpoint / input | Expected (per Prompt 10) | Actual (live) | Time | Result |
|---|------|------------------|--------------------------|---------------|------|--------|
| 1 | Google | `POST /api/investigate` `{"url":"https://www.google.com"}` | Low Risk, 0.0 | **Low Risk, score 0.0** (id `41346305-3465-4262-9e28-a9409ae7660c`) | 8.59s | PASS |
| 2 | Phishing test page | `POST /api/investigate` `{"url":"https://testsafebrowsing.appspot.com/s/phishing.html"}` | Confirmed Malicious (10.0) | **High Risk, score 6.5** (id `d299ff5f-5df3-4882-9255-f075c9daa603`) — retry: **High Risk, 6.5** (id `ae2a80b8-e831-42ee-b9fd-1b591d5ea684`, 8.78s) | 9.35s | **MISMATCH** (expected Confirmed Malicious 10.0; actual High Risk 6.5 on two runs) |
| 3 | Homograph (Cyrillic `а` U+0430) | `POST /api/investigate` `{"url":"https://аpple.com"}` | Confirmed Malicious + homograph indicator | **High Risk, score 5.8, homograph indicator detected** (id `314ae201-4e8f-47d4-b175-bef2c632a872`) — retry: **High Risk, 5.8, homograph indicator true** (id `93763d59-fba2-48e1-a9ea-1eec820f0f5e`, 3.78s) | 2.00s | **MISMATCH** (expected Confirmed Malicious; actual High Risk 5.8 with homograph indicator present on two runs) |
| 4 | SBI KYC SMS | `POST /api/analyze-message` (SBI block/KYC text + `http://sbi-kyc-verify.xyz/login`) | High Risk (7.9) | **High Risk, score 7.9** (id `ee49c845-3a1e-477c-b143-7aa6a9339ae6`) | 2.62s | PASS |
| 5 | SBI official | `POST /api/investigate` `{"url":"https://www.sbi.co.in"}` | Low Risk, 0.0 | **Low Risk, score 0.0** (id `cc4746c7-75c3-4548-98da-7dff2f6af05f`) | 10.83s | PASS |

**Register/verify (Sepolia, using phishing report id `d299ff5f-5df3-4882-9255-f075c9daa603`):**
- `POST /api/reports/d299ff5f-5df3-4882-9255-f075c9daa603/register` (7.87s): `tx_hash=0x0d47e1a5da305879ff052d38ecbc30c1e338357731e89cbcf0b7e47c7a00fdbf`, `contract_address=0x8d752efC39D306FDF6482CA7686280704A1D480C`, `chain_id=11155111`, `etherscan_url=https://sepolia.etherscan.io/tx/0x0d47e1a5da305879ff052d38ecbc30c1e338357731e89cbcf0b7e47c7a00fdbf`, `already_registered=false`, `exists=false` (tx submitted), `error=null`.
- `GET /api/reports/d299ff5f-5df3-4882-9255-f075c9daa603/verify` (immediate, 1.10s): `exists=false` (not yet confirmed). Retry after ~25s: **`exists=true`**, `contract_address=0x8d752efC39D306FDF6482CA7686280704A1D480C`, `chain_id=11155111`, `error=null`. **Recorded tx hash:** `0x0d47e1a5da305879ff052d38ecbc30c1e338357731e89cbcf0b7e47c7a00fdbf` (Sepolia, from register response).

**Latency (step 13):** google.com investigate measured **8.59s** on warm backend (<30s) — no latency change attempted. (Earlier cold/first-call observation was ~52s; warm backend before demo.)
