# Deployment and Runtime Boundaries

## Supported execution mode
CyberSentinel's authoritative workflow is local/offline replay. The FastAPI backend loads local model artifacts, reads the locally installed unlabelled hidden replay input, generates the three submission CSVs, and writes run history to local SQLite.

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

Vite proxies `/api` requests to `http://127.0.0.1:8000`. Install authorised inputs and trained model artifacts in the ignored local paths documented in `docs/evaluation.md`. Do not commit organiser data, model binaries, generated submissions, `.env` files, or local databases.

## Vercel deployment

The Vercel project must use the **FastAPI** framework preset, with `api/index.py` as the application entrypoint. This is important: the Vite preset treats each `api/*.py` file as a separate function and does not route all FastAPI decorators through the central application. The FastAPI preset mounts the full `api.index:app` router so every `/api/*` endpoint is served by the same application. The Vercel build command is version-controlled in `pyproject.toml` under `[tool.vercel.scripts]`; it installs the frontend dependencies, builds Vite, and copies `dist/` into `public/` for CDN serving. Keep the Vercel project install command on automatic detection so Python dependencies from `pyproject.toml` are installed. Do not override it with `npm ci` alone.

The repository is connected to a Vercel project and the frontend/API bundle can build. A preview deployment for `feat/cybersentinel-release-hardening` reached Vercel `READY` on 2026-10-31. The current production deployment is also reported as `READY`; this confirms deployment packaging, not end-to-end model readiness or official replay acceptance.

### Current deployment handoff (2026-11-15)

The latest `main` source includes the isolated `common 1` Supabase schema integration. GitHub's Python tests, static-security checks, and frontend build pass on the latest main commit. Vercel's project environment variables now point to `common 1`, but Vercel applies environment changes to a deployment only when that deployment is built.

The production alias still points to the older deployment built from commit `d3b061d`, before the common-schema integration. The old dedicated `jai-hack` Supabase project is now paused, so the old production deployment must be treated as **temporarily unavailable for authenticated backend operations** until a new production build is ready and the aliases are moved. Do not describe the current production alias as running the latest code.

Vercel rejected new deployment creation with `402 payment_required` / `api-deployments-free-per-day` and a 24-hour retry window. Do not repeatedly retry or upgrade the plan just to bypass the limit. After the quota window resets, deploy the latest `main` commit, wait for `READY`, then verify `/api/health`, `/api/models/status`, Supabase sign-up/sign-in, one authenticated replay write/read, and two-user RLS isolation before treating production as restored. Older preview deployments from intermediate commits are not suitable substitutes for the latest main build.

Important limitations:

- `data/processed/*` and `models/*` are intentionally ignored by Git. A standard Git-triggered Vercel deployment therefore does not contain the organiser evaluation dataset or fitted model artifacts.
- Without both model files, `/api/health` reports `model_ready: false` and inference endpoints return `503 MODEL_NOT_READY`. The UI can load while the model-backed product workflow remains unavailable.
- `POST /api/replay/run-official` remains disabled in the serverless runtime until verified model/input artifacts and durable submission-file storage are provisioned. Run the official challenge workflow with the documented offline runner; hosted audit history is still persisted to Supabase.
- `POST /api/replay/run-official` is a synchronous request. The current `vercel.json` config sets Python functions under `api/*.py` and `api/**/*.py` to `maxDuration: 300` seconds. This is a platform execution ceiling, not proof that a full hidden replay fits within it; run the official replay locally unless a separately tested background-job/artifact architecture is implemented.
- Local/offline runs also maintain a local SQLite convenience history (`data/cybersentinel_history.db`). On Vercel, `/api/replay/simulate` does not write SQLite: it stores run summaries, decisions, policies, and correlation groups in Supabase Postgres using the caller's JWT and RLS. Raw flow records and model artifacts are not stored in Postgres.
- Preview deployments should remain protected by Vercel SSO; use an authorised session for browser QA. Production custom domains are public.

Do not describe the Vercel deployment as a verified production SOC service until model/data provisioning, durable run storage, full replay execution, API routes, and browser workflows have been tested end-to-end in that environment.

## Public guest demonstration

The React application supports a public guest path when Supabase Auth is configured. On the sign-in screen, visitors can choose **Explore public demo without signing in**. Guest mode is intentionally read-only and exposes only:

- The overview and illustrative five-agent architecture.
- The browser-local CSV schema/label inspection tool. It does not upload the selected file or run inference.
- The public liveness/model-readiness status displayed by the overview.

Guest mode does not load /api/history or /api/overview, and it hides the Flow Inspector, replay, evidence-fusion, correlation, adaptive-defense, audit/history, and system-diagnostics screens. Authenticated analyst access remains available through Supabase Auth.

This is a presentation/demo boundary, not a replacement for server authorization. Sensitive API routes must continue to enforce Supabase bearer-token authentication and user ownership independently of frontend navigation. The public demo must never be used to expose private replay rows, generated submissions, or administrative operations.

## Supabase authentication and data boundary

The React app creates a Supabase client from VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY, restores the browser session, and subscribes to auth-state changes. The analyst sign-in/sign-up screen is application-level authentication; Vercel deployment protection is a separate setting. The API client forwards the Supabase access token as a bearer token when a session exists.

The API explicitly requires an authenticated user for private history and overview data, inference, replay, evaluation snapshots, submission downloads, system diagnostics, policy, and correlation operations. Keep those checks in the backend even when the corresponding controls are hidden from guest users. The anonymous role must not gain access to private history tables; keep RLS enabled and verify ownership isolation with separate test users before production use.

The shared Supabase project `common 1` is the active Auth and Postgres backend. CyberSentinel stores hosted replay summaries and derived audit records only in its isolated `cybersentinel` schema, selected explicitly with PostgREST profile headers. The existing `bharatsim`, `genomeguard`, and `public` schemas are not modified. The old dedicated `jai-hack` Supabase project is paused and retained as a rollback source; it is not the configured runtime backend.

Supabase is the durable store for hosted replay summaries and derived audit records, but it is not a substitute for durable job/artifact infrastructure. Vercel's filesystem remains ephemeral; official hidden replay input, trained model artifacts, and generated submission files are not provisioned by a standard Git deployment. Do not claim hosted official replay or full model-backed readiness until those artifact paths are separately provisioned and tested.

## Readiness checks

- `GET /api/health`: API liveness and model availability.
- `GET /api/models/status`: model artifact and agent metadata.
- `GET /api/system/diagnostics`: local model, dataset, submission, history DB and simulated-firewall status.
- `GET /api/replay/validate`: validates generated submission files against the original installed unlabelled hidden replay input.

Use `docs/evaluation.md` for training, evaluation, replay and local submission reproduction. Use `docs/release-hardening.md` for causal replay and CSV acceptance invariants.
