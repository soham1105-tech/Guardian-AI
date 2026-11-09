<div align="center">

# Guardian.AI

**Deterministic phishing investigation with an explainable AI verdict — for suspicious links, emails, and messages — plus on-chain report integrity verification.**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=flat&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-19-61DAFB?style=flat&logo=react&logoColor=black)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-8-646CFF?style=flat&logo=vite&logoColor=white)](https://vite.dev/)

</div>

## Live demo

- **Backend (Render):** `https://guardian-ai-backend-sqgq.onrender.com` (live)
- **Frontend (Vercel):** `https://guardian-ai-six-phi.vercel.app/`

## What the product does

Guardian.AI helps users **check before they click**. Submit a suspicious URL/domain, paste an SMS/WhatsApp-style message, or upload a raw `.eml` email. Guardian.AI runs deterministic checks (URL/domain normalization, homograph/typosquat and suspicious-TLD signals, SSRF-safe redirect/DNS/TLS probing, and reputation/threat-intel evidence with a vendor-count threshold) and produces an **explainable verdict** with a 0–10 risk score and a fixed risk class.

**Risk classes (only these five):** `Low Risk`, `Suspicious`, `High Risk`, `Confirmed Malicious`, `Inconclusive`. The class is determined by score + qualifying threat-intel match (Prompt 8b): a single-vendor reputation flag (e.g. 1/92) is recorded as an informational note and **never** triggers `Confirmed Malicious`; `Confirmed Malicious` requires score 9–10 **and** a qualifying threat-intel match. A valid certificate does not mean a website is safe.

Reports can be **anchored on-chain** (Hardhat local for dev/demo; Sepolia for testnet) and later **verified** for integrity.

## Architecture

| Layer | Tech | Role |
|---|---|---|
| Backend | FastAPI (Python), SQLite | Investigation/message/email analysis APIs, deterministic scoring, threat-intel aggregation, report storage, Web3 registry client |
| Frontend | React 19 + Vite + Tailwind (v4) | Investigation UI (email/link/message), report/tabs, on-chain register/verify actions |
| Database | SQLite (local/dev; ephemeral on Render free tier) | Emails, analyses, reports (`DATABASE_URL`, default `sqlite:///./guardian.db`) |
| Blockchain | Hardhat + Solidity (`ReportRegistry`) | Local chain for reproducible demo; Sepolia for testnet verification |
| AI verdict (optional) | Groq (configurable model) | Explains the evidence; deterministic verdict/class rules remain authoritative |

## Setup (local)

### Backend
```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate   |   macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
# copy backend/.env.example to backend/.env and set keys as needed (never commit .env)
# Windows (bash): CORS_ORIGINS="http://localhost:5173,http://127.0.0.1:5173" WEB3_RPC_URL="http://127.0.0.1:8545" .venv/Scripts/python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### Frontend
```bash
cd frontend
npm install
# optional: copy frontend/.env.example to frontend/.env and set VITE_API_URL
npm run dev
```

### Blockchain (local Hardhat demo)
```bash
cd blockchain
npm install
npx hardhat node
# in another terminal:
npx hardhat run scripts/deploy.js --network localhost
```
This deploys `ReportRegistry` locally and writes `backend/contract.json` (address/ABI; no secrets). Start the backend with `WEB3_RPC_URL=http://127.0.0.1:8545` to enable register/verify.

## API endpoints

Base: `http://localhost:8000` (dev). Main routes (all under `/api`):

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/investigate` | Investigate a URL/domain (`{"url":"..."}`) |
| POST | `/api/analyze-message` | Analyze pasted SMS/text/WhatsApp-style message (`{"text":"..."}`) |
| POST | `/api/upload` | Upload a `.eml` email |
| POST | `/api/analyze/{email_id}` | Analyze an uploaded email |
| GET | `/api/analyses` | List analyses (legacy/list view) |
| GET | `/api/analyses/{email_id}` | Get an analysis |
| GET | `/api/reports` | List reports/investigations |
| GET | `/api/reports/{report_id}` | Get a report |
| POST | `/api/reports/{report_id}/register` | Register report hash on-chain |
| GET | `/api/reports/{report_id}/verify` | Verify report hash/integrity on-chain |

## Six test cases

| Case | Input | Expected |
|---|---|---|
| Suspicious link | `POST /api/investigate` `{"url":"https://testsafebrowsing.appspot.com/s/phishing.html"}` | High Risk or Confirmed Malicious |
| Homograph (Cyrillic `а` in `apple`) | `POST /api/investigate` `{"url":"https://аpple.com"}` | Flagged; homograph indicator present |
| Fake SBI KYC SMS | `POST /api/analyze-message` `{"text":"Dear customer, your SBI account will be blocked today. Verify KYC now at http://sbi-kyc-verify.xyz/login"}` | High Risk or Confirmed Malicious |
| Benign | `POST /api/investigate` `{"url":"https://www.google.com"}` | Low Risk |
| Benign | `POST /api/investigate` `{"url":"https://www.github.com"}` | Low Risk |
| Benign (real bank) | `POST /api/investigate` `{"url":"https://www.sbi.co.in"}` | Low Risk |

See [TESTING.md](TESTING.md) for actual results.

## Web3 verification

- **Sepolia (testnet, live / verified):** `chain_id=11155111`, contract **`0x8d752efC39D306FDF6482CA7686280704A1D480C`** — [Etherscan (address)](https://sepolia.etherscan.io/address/0x8d752efC39D306FDF6482CA7686280704A1D480C).
  - Deployment tx: `0x5c98491f51012dc81bad0c012303c90f6d01406ec46d1df3203de69ece6a94c0` ([Etherscan tx](https://sepolia.etherscan.io/tx/0x5c98491f51012dc81bad0c012303c90f6d01406ec46d1df3203de69ece6a94c0))
  - Register tx: `0x9f592ba27b26ce990bc47ff3f0a5032b158dcb249b98b0ab8aceb50f8c2e4f2e` ([Etherscan tx](https://sepolia.etherscan.io/tx/0x9f592ba27b26ce990bc47ff3f0a5032b158dcb249b98b0ab8aceb50f8c2e4f2e))
  - (`contract_address` matches, `chain_id` 11155111, report registered/verified). Configure backend `WEB3_RPC_URL`/`PRIVATE_KEY` on the host (Render dashboard) — never commit keys.
- **Local (reproducible dev demo):** Hardhat `localhost`, `chain_id=31337`, contract `0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9` (local deploy). Sample register tx `0x781240ba01ff5b134e2de6e32a876309f2591debd37817a84627e7a0d6657749`; local chain hashes are not Etherscan-verifiable.

## Documentation & demo

- [TESTING.md](TESTING.md) — test cases, actual results, endpoint status
- [DEMO_SCRIPT.md](DEMO_SCRIPT.md) — 2-minute demo flow + recording checklist
- [SUBMISSION_CHECKLIST.md](SUBMISSION_CHECKLIST.md) — HackMatrix deliverables/status (check dashboard for exact format)
- [DEPLOY.md](DEPLOY.md) — Vercel/Render/Sepolia deployment notes
- [Project Theory Document](docs/PhishGuard_AI_Project_Theory.docx) (legacy filename retained; do not rename files/routes)
