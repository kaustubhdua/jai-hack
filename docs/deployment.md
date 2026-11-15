# Deployment and Runtime Boundaries

## Supported execution mode

CyberSentinel's authoritative workflow is local/offline replay. The FastAPI backend loads the checked-in model artifacts, reads an installed unlabelled replay input, generates the three submission CSVs, and writes local convenience history to SQLite.

Install and run the local stack from the repository root:

```bash
python -m pip install -e ".[dev,ml]"
npm install
uvicorn api.index:app --host 127.0.0.1 --port 8000
```

In a second terminal:

```bash
npm run dev
```

Vite proxies /api requests to http://127.0.0.1:8000. Install authorized inputs and trained model artifacts in the ignored local paths documented in docs/evaluation.md. Do not commit organizer data, generated submissions, .env files, or local databases.

## Vercel deployment

The Vercel project uses the Vite framework preset so the React frontend is served as static assets. vercel.json rewrites /api/* requests to api/index.py; the ASGI middleware restores the original request path before FastAPI route matching. Keep automatic install/build settings so npm and Python dependencies are installed correctly. Do not switch to the FastAPI framework preset: that can replace the static React entry point.

The Vercel Hobby build quota has previously blocked deployments. Do not repeatedly retry or upgrade the plan to bypass a quota. Deploy the latest tested branch after the quota resets, wait for READY, then verify the exact deployment URL and production alias independently.

## Backend: Neon Postgres, no Supabase

Supabase has been removed from the CyberSentinel runtime. The frontend has no Supabase SDK, the API has no Supabase Auth/PostgREST calls, and Vercel must not contain Supabase runtime configuration.

The hosted backend uses a dedicated Neon Postgres Free project. It is separate from all other applications and uses the cybersentinel schema. Vercel's server-only sensitive variables are:

- DATABASE_URL: pooled Neon Postgres connection string using the restricted cybersentinel_app role.
- AUTH_SECRET: random HMAC signing key, at least 32 characters.

Both variables are set for Production, Preview, and Development. Neither is exposed to the browser. Do not add VITE_DATABASE_URL, VITE_AUTH_SECRET, or any provider key to the frontend.

The API provides first-party account endpoints:

- POST /api/auth/signup
- POST /api/auth/login
- GET /api/auth/me

Passwords are PBKDF2-HMAC-SHA256 hashed; bearer tokens are HMAC-SHA256 signed and expire after 12 hours. The API derives user identity from a verified token and filters audit reads by that user. Replay child events are constrained to a replay run owned by the same user. The browser clears its token on sign-out. Email verification and password recovery are not implemented; do not imply otherwise.

The Neon project uses a 0.25 CU compute with scale-to-zero. Expect cold-start latency after inactivity. Monitor the Free plan's storage, compute-active time, and network-transfer allowances. Do not store raw flow records or model binaries in Postgres.

See docs/neon-backend.md for schema, role, authentication, and local setup details.

## Artifact and replay boundaries

- data/processed/* and most local training inputs are intentionally ignored by Git. A normal Git deployment therefore does not automatically contain organizer hidden data.
- Both model artifacts are checked into the repository and have a runtime smoke test, but that alone does not prove the live deployment loaded them.
- POST /api/replay/run-official remains disabled in the serverless runtime until verified model/input artifacts and durable submission-file storage are provisioned. Run official challenge replay with the documented offline runner unless a separately tested background-job/artifact architecture is implemented.
- Vercel's filesystem is ephemeral. Hosted replay summaries and derived audit events are durable in Neon; generated submission files and hidden replay input are not.
- The configured Python function maximum duration is 300 seconds. This is a platform ceiling, not proof that a full replay fits within it.
- A Vercel READY deployment proves build/deployment state, not end-to-end model readiness, account flow, tenant isolation, full replay success, or official organizer acceptance.

## Public guest demonstration

The React application opens in a public read-only guest mode. Visitors can explore the overview and five-agent architecture and inspect a CSV locally in their browser; the selected file is not uploaded by that inspection. Guest mode does not access private history or privileged analysis routes.

Signing in opens the private analyst workspace. The frontend navigation is only a presentation boundary: every private API route must continue to enforce token authentication and user ownership on the server.

## Readiness checks

- GET /api/health: API liveness and model availability.
- GET /api/models/status: model artifact and agent metadata.
- GET /api/system/diagnostics: local model, dataset, submission, database and simulated-firewall status.
- GET /api/auth/me: current account/session validation.
- GET /api/history: private replay and evaluation history.
- GET /api/replay/validate: validates generated submission files against the original installed unlabelled hidden replay input.

Before declaring production ready, verify signup, login, invalid credentials, expired token handling, authenticated analysis, replay persistence, history reads, and cross-user isolation against the deployed API and Neon database. Then run a real browser walkthrough of the production alias.

Use docs/evaluation.md for training, evaluation, replay and local submission reproduction. Use docs/release-hardening.md for causal replay and CSV acceptance invariants.
