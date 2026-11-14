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

The repository is connected to a Vercel project and the frontend/API bundle can build. A preview deployment for `feat/cybersentinel-release-hardening` reached Vercel `READY` on 2026-10-31. The current production deployment is also reported as `READY`; this confirms deployment packaging, not end-to-end model readiness or official replay acceptance.

Important limitations:

- `data/processed/*` and `models/*` are intentionally ignored by Git. A standard Git-triggered Vercel deployment therefore does not contain the organiser evaluation dataset or fitted model artifacts.
- Without both model files, `/api/health` reports `model_ready: false` and inference endpoints return `503 MODEL_NOT_READY`. The UI can load while the model-backed product workflow remains unavailable.
- `POST /api/replay/run-official` remains disabled in the serverless runtime until verified model/input artifacts and durable submission-file storage are provisioned. Run the official challenge workflow with the documented offline runner; hosted audit history is still persisted to Supabase.
- `POST /api/replay/run-official` is a synchronous request. The current `vercel.json` config sets Python functions under `api/*.py` and `api/**/*.py` to `maxDuration: 300` seconds. This is a platform execution ceiling, not proof that a full hidden replay fits within it; run the official replay locally unless a separately tested background-job/artifact architecture is implemented.
- Local/offline runs also maintain a local SQLite convenience history (`data/cybersentinel_history.db`). On Vercel, `/api/replay/simulate` does not write SQLite: it stores run summaries, decisions, policies, and correlation groups in Supabase Postgres using the caller's JWT and RLS. Raw flow records and model artifacts are not stored in Postgres.
- Preview deployments are protected by Vercel SSO in the current project configuration, so external browser QA requires an authorised session.

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

Supabase is not a substitute for durable job infrastructure. The current serverless runtime still has ephemeral local filesystem/SQLite behavior, and model/dataset artifacts are not provisioned by a standard Git deployment. Do not claim durable hosted replay history or production model-backed operation until those infrastructure paths are separately verified.

## Readiness checks

- `GET /api/health`: API liveness and model availability.
- `GET /api/models/status`: model artifact and agent metadata.
- `GET /api/system/diagnostics`: local model, dataset, submission, history DB and simulated-firewall status.
- `GET /api/replay/validate`: validates generated submission files against the original installed unlabelled hidden replay input.

Use `docs/evaluation.md` for training, evaluation, replay and local submission reproduction. Use `docs/release-hardening.md` for causal replay and CSV acceptance invariants.
