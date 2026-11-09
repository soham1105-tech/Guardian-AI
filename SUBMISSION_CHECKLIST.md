# Guardian.AI — HackMatrix Submission Checklist

The nine deliverables from the problem statement. **Do not invent the submission format** — check the HackMatrix dashboard for the exact format and portal fields before submitting.

| # | Deliverable | Status | Notes / next step |
|---|-------------|--------|-------------------|
| 1 | Working prototype | **Ready (local)** | React + Vite frontend, FastAPI backend, SQLite, Hardhat local chain. Run backend, frontend, and `npx hardhat node` + deploy; see `README.md` setup. |
| 2 | Public GitHub repo | **Ready** | Remote `origin` points to the configured GitHub repo (verified via `git remote -v`). Verify the repo is public on GitHub and the latest commit is pushed (`git log --oneline -5`). |
| 3 | AI demo | **Ready** | AI verdict/explanation shown in report UI (Groq-backed when configured; rule-based fallback when unavailable). Demo step 3 in `DEMO_SCRIPT.md` covers message analysis. |
| 4 | Cybersecurity demo including TLS | **Ready** | URL investigation covers headers/URLs/IOCs; TLS/Website Security evidence shown in report. Demo steps 1–2 in `DEMO_SCRIPT.md` (“a valid certificate does not mean the website is safe”). |
| 5 | Web3 demo (testnet or reproducible local chain + contract address + transaction reference) | **Ready (reproducible local chain)** | Contract: `0xCf7Ed3AccA5a467e9e704C703E8D87F634fB0Fc9` (Hardhat localhost, chain 31337; redeployed this run — see `backend/contract.json`). Example tx: `0xa715dd711eebe9702163db7fd2f4e884cb9628427ce57bb498dc1159a205bd6a` (report `8f410c34-9919-4473-8018-95549c586022`, verify passed). **Note:** local chain is ephemeral — keep node running for demo and re-record tx/address if restarted. |
| 6 | Verification evidence | **Ready** | On-chain register+verify passed (exists, verdict `Low Risk`); see `TESTING.md` “Web3 verification evidence”. |
| 7 | Technical documentation | **Ready** | `README.md` (architecture, setup, API endpoints, six test cases, Web3 section) + project theory document in `docs/` (kept at its original filename/path). |
| 8 | Testing report | **Ready** | `TESTING.md` with six cases + actuals, pytest 98 passed, `vite build` success, per-endpoint status, risk-class audit. |
| 9 | Live demo | **TODO (user action)** | Record the 2-minute demo using `DEMO_SCRIPT.md`. **Next step:** start backend/frontend/hardhat, record at 1920×1080 with no secrets visible, follow the 5 shots + closing line, then upload per the HackMatrix dashboard format. |

## Final user actions (after this repo state)

1. Record the 2-minute demo video using `DEMO_SCRIPT.md`.
2. Check the **HackMatrix dashboard** for the exact submission format (fields, links, upload types) — do not guess.
3. Submit before **Tue 10 Nov 2026, 10pm IST**.

## Integrity notes

- Verdict rules, 0–10 numeric scale, and risk-class mapping unchanged (only the five allowed `risk_class` values are returned).
- No paid APIs or new packages added.
- `LICENSE` file: **none present at repo root** (not created/modified). The single attribution line at the top of `README.md` is preserved.
