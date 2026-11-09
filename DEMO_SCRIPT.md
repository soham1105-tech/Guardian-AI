# Guardian.AI — 2-Minute Demo Script

One line per shot. Follow this exact flow.

1. **Suspicious link** — Paste `https://testsafebrowsing.appspot.com/s/phishing.html` into the command bar and run the investigation; show the report verdict (High Risk) and the risk gauge.
2. **TLS tab** — Open the TLS / Website Security view for the report and say: *“A valid certificate does not mean the website is safe.”*
3. **Bank SMS** — Switch to the message analysis flow and paste: `Dear customer, your SBI account will be blocked today. Verify KYC now at http://sbi-kyc-verify.xyz/login`; show the AI / verdict result (High Risk).
4. **Register on-chain** — Click **Register on-chain** on a report; show the transaction hash and contract address returned.
5. **Verify on-chain** — Click **Verify on-chain**; show the integrity check passing (anchored timestamp and verdict match).
6. **Close** — “One report, three proofs — the URL, the certificate, and the chain.”

## Recording checklist

- [ ] Backend (`uvicorn` on `http://127.0.0.1:8000`), frontend (`vite` on `http://127.0.0.1:5173`), and Hardhat node (`npx hardhat node` on `http://127.0.0.1:8545`) are all running; contract deployed (`backend/contract.json` points to the live local chain).
- [ ] Screen recording at **1920×1080**; browser zoom/readable UI; no cluttered desktop notifications.
- [ ] **No passwords or API keys visible on screen** (no `.env`, no terminal history with secrets, no browser autofill of secrets).
- [ ] Use the exact inputs above for a clean, reproducible run; keep the Hardhat node running through steps 4–5 (the local chain is ephemeral).
- [ ] If a live threat-intel provider is unavailable, the demo still shows the deterministic/local evidence and verdict — call that out briefly if it happens.
