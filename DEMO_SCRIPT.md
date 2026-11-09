# Guardian.AI — 2-Minute Demo Script

**Goal:** show deterministic checks + explainable verdict, TLS context, message analysis, and Web3 integrity verification. One line per shot.

## Shot list (≈2 minutes)

1. **Suspicious link (investigate):** Paste `https://testsafebrowsing.appspot.com/s/phishing.html` into *Check a link* and run. Show the report verdict (**High Risk / Confirmed Malicious**), the risk score, and the key indicators/evidence. *Voiceover:* “Guardian.AI runs deterministic checks and live reputation signals before explaining the risk.”
2. **TLS tab (certificate context):** Open the **TLS / certificate** (or TLS-related) section of the report. Point at the certificate/status details. *Voiceover:* “A valid certificate does not mean the website is safe — Guardian.AI shows certificate context alongside reputation and domain signals.”
3. **Bank SMS (message analysis):** Switch to *Paste a message* and paste: `Dear customer, your SBI account will be blocked today. Verify KYC now at http://sbi-kyc-verify.xyz/login`. Run and show the **High Risk / Confirmed Malicious** verdict and AI/deterministic explanation. *Voiceover:* “The same evidence-driven approach applies to phishing SMS and chat messages.”
4. **Register on-chain:** On the report, click **Register on-chain**. Show the **transaction hash** (and contract/chain info). *Voiceover:* “We anchor the report hash on-chain so the result can be audited later.”
5. **Verify on-chain:** Click **Verify on-chain** (or open verification). Show the **integrity check passing** (`exists=true`, verdict/submitter/timestamp match). *Voiceover close:* **“One report, three proofs — the URL, the certificate, and the chain.”**

## Recording checklist

- [ ] **Services running:** backend (`uvicorn` on `127.0.0.1:8000` with required env, e.g. `CORS_ORIGINS` incl. frontend origin; `WEB3_RPC_URL=http://127.0.0.1:8545` for local chain), frontend (`npm run dev`, e.g. `http://localhost:5173`), and (for steps 4–5) Hardhat node (`npx hardhat node` on `8545` with a deployed contract loaded by the backend). For a **Sepolia** demo, use a deployed Sepolia contract + funded deployer key in backend env and show the Etherscan transaction link instead of local chain IDs.
- [ ] **Screen recording:** 1920×1080, readable UI zoom, cursor visible.
- [ ] **Privacy/safety:** **No passwords, API keys, private keys, seed phrases, or `.env` contents visible** on screen (terminal history, editor tabs, browser devtools storage, or notifications). Use test/demo data only.
- [ ] **Browser clean:** no console errors visible during the flow; no failed requests on load (check DevTools quickly before recording).
- [ ] **Warm-up:** if using Render/free tier, open the backend `/` or `/docs` first to avoid cold-start delay on camera.
- [ ] **Timing:** rehearse once; keep to ~2 minutes; pause briefly after the on-chain tx/verify so the hash and “integrity check passing” are readable.
