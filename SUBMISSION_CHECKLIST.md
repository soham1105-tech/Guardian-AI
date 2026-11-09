# Guardian.AI — Submission Checklist (HackMatrix)

**Deadline:** Tue 10 Nov 2026, 10:00 PM IST. **Do not invent the submission format** — confirm the exact upload/link fields and format on the HackMatrix dashboard before submitting.

## Deliverables (9)

| # | Deliverable | Status | Evidence / next step |
|---|---|---|---|
| 1 | Working prototype | **READY (local) / VERIFY (hosted)** | Backend (FastAPI) + frontend (React/Vite) + optional Hardhat chain run locally; `vite build` succeeds; core flows verified (investigate, analyze-message, register/verify). *Next:* ensure hosted URLs are live and warmed (Render sleeps on free tier) before demo. |
| 2 | Public GitHub repo | **READY** | Remote: `origin https://github.com/soham1105-tech/Guardian-AI.git` (push/fetch). Repo confirmed public on GitHub; latest commit pushed (`34294db`). |
| 3 | AI demo | **READY** | Deterministic checks + explainable AI verdict path (Groq-backed when `GROQ_API_KEY` is configured). *Next:* set a valid `GROQ_API_KEY` in the demo environment so the live LLM explanation (not fallback) is shown; do not expose the key on screen. |
| 4 | Cybersecurity demo including TLS | **READY** | Link investigation covers domain/redirect/DNS/reputation and TLS/certificate context; homograph detection verified (`https://аpple.com`, Cyrillic `а` → homograph indicator). *Next:* in the demo, open the TLS/certificate section and state “a valid certificate does not mean the website is safe.” |
| 5 | Web3 demo (testnet or reproducible local chain + contract address + transaction reference) | **READY** | **Sepolia (live/verified):** contract `0x8d752efC39D306FDF6482CA7686280704A1D480C` ([Etherscan address](https://sepolia.etherscan.io/address/0x8d752efC39D306FDF6482CA7686280704A1D480C)); deployment tx `0x5c98491f51012dc81bad0c012303c90f6d01406ec46d1df3203de69ece6a94c0` ([Etherscan](https://sepolia.etherscan.io/tx/0x5c98491f51012dc81bad0c012303c90f6d01406ec46d1df3203de69ece6a94c0)); register tx `0x9f592ba27b26ce990bc47ff3f0a5032b158dcb249b98b0ab8aceb50f8c2e4f2e` ([Etherscan](https://sepolia.etherscan.io/tx/0x9f592ba27b26ce990bc47ff3f0a5032b158dcb249b98b0ab8aceb50f8c2e4f2e)). **Local fallback (reproducible):** Hardhat localhost `chain_id=31337`, contract `0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9`, register tx `0x781240ba01ff5b134e2de6e32a876309f2591debd37817a84627e7a0d6657749`, verify `exists=true`. |
| 6 | Verification evidence | **READY** | `TESTING.md` (6 cases with actuals, pytest `108 passed`, `vite build` success, endpoint status, on-chain register/verify output). *Next:* capture screenshots/short clip if the dashboard requires visual evidence. |
| 7 | Technical documentation | **READY** | `README.md` (architecture, setup, endpoints, 6 test cases, Web3), `DEPLOY.md`, `docs/` (legacy theory doc filename retained). README Sepolia values filled (contract + both tx hashes); live frontend and backend URLs recorded; nothing outstanding here. |
| 8 | Testing report | **READY** | `TESTING.md`. |
| 9 | Live demo | **TODO (user action)** | Record the 2-minute demo using `DEMO_SCRIPT.md`. *Next:* record at 1920×1080 with backend+frontend+Hardhat (or Sepolia) running, **no keys/passwords visible**; upload per the HackMatrix dashboard format. |

## Pre-submit checks

- [ ] `cd backend && python -m pytest tests/ -q` green.
- [ ] `cd frontend && npm run build` succeeds.
- [ ] Repo-wide legacy-name sweep reviewed (only allowed/operational exceptions reported in the Prompt 7 final reply: README attribution line kept as required, legacy doc filename in link retained because files/routes must not be renamed, real Render hostname in keep-alive workflow retained as the actual deployed service — the keep-alive workflow now pings `https://guardian-ai-backend-sqgq.onrender.com` (the actual hostname), local untracked `.db` artifact if present). **No LICENSE file exists** in repo — report noted.
- [ ] `.env` / private keys **not** committed; dashboard secrets set.
- [ ] **Exact submission format checked on HackMatrix dashboard** (links/files/fields) — do not guess.
- [ ] Submit before **Tue 10 Nov 2026, 10:00 PM IST**.
