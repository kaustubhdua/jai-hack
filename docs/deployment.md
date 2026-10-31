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

The repository is connected to a Vercel project and the frontend/API bundle can build. A preview deployment for `feat/cybersentinel-release-hardening` reached Vercel `READY` on 2026-10-31. This confirms deployment packaging, not end-to-end model readiness or official replay acceptance.

Important limitations:

- `data/processed/*` and `models/*` are intentionally ignored by Git. A standard Git-triggered Vercel deployment therefore does not contain the organiser evaluation dataset or fitted model artifacts.
- Without both model files, `/api/health` reports `model_ready: false` and inference endpoints return `503 MODEL_NOT_READY`. The UI can load while the model-backed product workflow remains unavailable.
- `POST /api/replay/run-official` is a synchronous request. `vercel.json` currently sets Python function `maxDuration` to 30 seconds. A full hidden replay may exceed that limit; run the official replay locally unless a separately tested background-job/artifact architecture is implemented.
- The backend stores run history in local SQLite (`data/cybersentinel_history.db`). Serverless filesystem state is not a durable shared database across invocations or instances.
- Preview deployments are protected by Vercel SSO in the current project configuration, so external browser QA requires an authorised session.

Do not describe the Vercel deployment as a verified production SOC service until model/data provisioning, durable run storage, full replay execution, API routes, and browser workflows have been tested end-to-end in that environment.

## Supabase

Supabase is currently an optional frontend authentication integration. Guest mode is available when it is not configured. The current FastAPI replay/history implementation uses local files and SQLite; it does not persist replay runs through Supabase or enforce the documented `auth.uid()` row-level security policy. Do not claim Supabase-backed replay persistence or RLS enforcement until those backend integrations and policy tests exist.

## Readiness checks

- `GET /api/health`: API liveness and model availability.
- `GET /api/models/status`: model artifact and agent metadata.
- `GET /api/system/diagnostics`: local model, dataset, submission, history DB and simulated-firewall status.
- `GET /api/replay/validate`: validates generated submission files against the original installed unlabelled hidden replay input.

Use `docs/evaluation.md` for training, evaluation, replay and local submission reproduction. Use `docs/release-hardening.md` for causal replay and CSV acceptance invariants.
