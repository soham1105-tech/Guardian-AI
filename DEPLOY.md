# Guardian.AI — Deployment (Vercel + Render + Sepolia)

This app runs in production from **environment variables only** (no hardcoded localhost URLs, no committed keys).

- **Frontend** (React/Vite): Vercel
- **Backend** (FastAPI): Render
- **On-chain registry** (optional): Sepolia testnet via Hardhat (local Hardhat still works for dev)

> **Render free tier notes (important):** SQLite is **ephemeral** — `guardian.db` (and any legacy local `*.db`) / reports reset on restart or redeploy. Re-run the demo cases after a restart. The service **sleeps after inactivity**; the first request can take ~30s to wake. **Open the backend URL once before any demo** (e.g. `GET /` or `/docs`) so it’s warm.

## (a) Push the repo to GitHub

1. Ensure no real secrets are committed (`backend/.env`, `frontend/.env`, `blockchain/.env` must stay untracked — see `.gitignore`).
2. Commit the deployment-readiness changes and push:
   ```bash
   git add -A
   git commit -m "Make app deployment-ready (env-based config, Render/Vercel/Sepolia)"
   git push origin <your-branch>
   ```

## (b) Vercel (frontend)

1. In Vercel: **Add New → Project → Import** the GitHub repo.
2. **Framework preset:** Vite.
3. **Root directory:** `frontend` (so Vercel builds the Vite app there).
4. **Environment variable:** `VITE_API_URL` = your Render backend URL (origin is fine, e.g. `https://guardian-ai-backend-sqgq.onrender.com`; the app appends `/api` if needed).
5. Deploy. Note the Vercel domain (e.g. `https://your-app.vercel.app`) for CORS.

## (c) Render (backend)

1. In Render: **New → Web Service** from the repo. You can use `render.yaml` (Blueprint) or configure manually:
   - **Root directory:** `backend`
   - **Build command:** `pip install -r requirements.txt`
   - **Start command:** `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - **Plan:** Free
2. Set environment variables in the Render dashboard (all `sync: false` in `render.yaml` — set them in the dashboard, not in the file):
   - `GROQ_API_KEY` — from your local `backend/.env` (Groq console)
   - `CORS_ORIGINS` — include the Vercel domain plus local dev if desired, comma-separated, e.g. `https://your-app.vercel.app,http://localhost:5173,http://127.0.0.1:5173`
   - `WEB3_RPC_URL` — Sepolia RPC URL (e.g. from Alchemy/Infura) if using on-chain registration; otherwise `http://127.0.0.1:8545` (registry will be unavailable on Render)
   - `PRIVATE_KEY` — the **deployer** account private key for signing registry transactions on Sepolia. **Never commit it.** Leave empty only if you are not using a remote chain that requires signing.
3. Deploy and copy the backend URL (e.g. `https://....onrender.com`). Ensure `VITE_API_URL` on Vercel points to it and redeploy the frontend if needed.

## (d) Sepolia (on-chain registry)

1. Get test ETH for the deployer account: https://sepoliafaucet.com (or another Sepolia faucet).
2. Create `blockchain/.env` (do **not** commit) from `blockchain/.env.example`:
   ```env
   SEPOLIA_RPC_URL=https://sepolia.infura.io/v3/<YOUR_PROJECT_ID>   # or Alchemy/other RPC
   PRIVATE_KEY=<deployer_private_key_with_test_ETH>
   ```
3. Deploy the contract (writes `backend/contract.json` with address + ABI):
   ```bash
   cd blockchain
   npm install
   npx hardhat run scripts/deploy.js --network sepolia
   ```
4. **Record** the printed **contract address** and the deployment **transaction hash** (from the deploy tx in your wallet/explorer, or the Hardhat output context). Verify on https://sepolia.etherscan.io/address/<CONTRACT_ADDRESS>.
5. For the hosted backend to register reports on Sepolia, set Render `WEB3_RPC_URL` to the same Sepolia RPC, set `PRIVATE_KEY` to the deployer key, and ensure the deployed `backend/contract.json` (or the address/ABI the backend reads) matches the Sepolia deployment. *Note: if the backend runs on Render from a clean build, commit the updated `backend/contract.json` from the Sepolia deploy only if it contains **no secrets** (it contains address/ABI/network metadata — safe) so the service can load it.*

## (e) Verification checklist

- [ ] `GET <BACKEND_URL>/` returns `{"status":"ok",...}` (wake Render first on free tier).
- [ ] Frontend loads and can reach the backend (no CORS errors in browser console).
- [ ] `POST <BACKEND_URL>/api/investigate` with `{"url":"https://www.google.com"}` → **Low Risk**.
- [ ] `POST <BACKEND_URL>/api/investigate` with `{"url":"https://testsafebrowsing.appspot.com/s/phishing.html"}` → **High Risk** or **Confirmed Malicious**.
- [ ] (If Sepolia configured) Register a report and confirm the response includes `tx_hash` and, for Sepolia, `etherscan_url` pointing to `https://sepolia.etherscan.io/tx/...`.

## Local dev (unchanged)

- Backend: `cd backend && python -m uvicorn app.main:app --host 127.0.0.1 --port 8000` (reads `backend/.env`; defaults work without `CORS_ORIGINS`/`WEB3_RPC_URL`/`PRIVATE_KEY`).
- Frontend: `cd frontend && npm run dev` (uses `VITE_API_URL` fallback to `http://localhost:8000`).
- Hardhat local: `cd blockchain && npx hardhat node` then `npx hardhat run scripts/deploy.js --network localhost` (uses unlocked account; leave `PRIVATE_KEY` unset).

## Security

- **Never** commit real `.env` files or private keys. `.gitignore` covers `.env` / `.env.*` (with `.env.example` allowed).
- Only `GROQ_API_KEY`, `CORS_ORIGINS`, `WEB3_RPC_URL`, `PRIVATE_KEY` (and optional intel keys) belong in backend env; keep secrets in Render/Vercel dashboards.
