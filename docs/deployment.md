# Deployment and Runtime Boundaries

## Account-free architecture

CyberSentinel is a public, account-free application. It has no signup, login, logout, user table, bearer tokens, identity provider, Supabase, Neon, PostgreSQL, or hosted database.

- React calls same-origin `/api/*` FastAPI routes without authorization headers.
- The API exposes supported analysis and replay operations publicly. Inputs are validated and model/data prerequisites are checked server-side.
- Local run summaries are written to a SQLite file on the machine running the backend.
- Hosted Vercel functions are stateless. Their writable filesystem is ephemeral, so the hosted API does not claim to persist replay history or audit events.
- No raw flow records are written to a third-party database. Browser CSV inspection stays in the browser; analysis uploads occur only when the user explicitly invokes an API analysis action.

## Local installation

```bash
git clone https://github.com/kaustubhdua/jai-hack.git
cd jai-hack
python -m pip install -e ".[dev,ml]"
npm install
uvicorn api.index:app --host 127.0.0.1 --port 8000
```

In a second terminal:

```bash
npm run dev
```

Vite proxies `/api` requests to `http://127.0.0.1:8000`. Local history is stored in `data/cybersentinel_history.db`. Keep local datasets, generated submissions, .env files, and database files out of Git.

## Vercel deployment

The Vercel project uses the Vite framework preset so the React frontend is served as static assets. `vercel.json` rewrites `/api/*` requests to `api/index.py`; the ASGI middleware restores the original request path. Keep automatic install/build settings and the Vite framework preset.

Vercel Python functions are configured with a 300-second maximum duration. This is a platform ceiling, not proof that a full organizer replay fits. The Vercel Hobby build quota has previously blocked deployments; do not repeatedly retry or upgrade the plan to bypass a quota.

## Artifact and replay boundaries

- Model artifacts are checked into the repository and have a runtime smoke test. Their presence does not by itself prove that the live deployment loaded them.
- `data/processed/*` and organizer training/hidden inputs are intentionally git-ignored. A Git deployment does not automatically include them.
- Official hidden replay and submission generation are local/offline operations. The hosted endpoint returns an explicit unavailable response rather than claiming it can write durable submission files.
- Local SQLite history is available only when running the backend on a persistent local machine. Hosted history returns an explicit empty, non-persistent state.
- Replay correlation groups are held only in the current API process; they are not durable across serverless instances or cold starts.

## Public API

- `GET /api/health` — API and model readiness.
- `GET /api/models/status` — model artifact and agent metadata.
- `GET /api/system/diagnostics` — model/data/submission artifact diagnostics; no authentication.
- `GET /api/history` — local SQLite history or an explicit stateless-hosted response.
- `POST /api/analyze` and `POST /api/analyze/batch` — stateless model inference.
- `POST /api/replay/simulate` — chronological replay over supplied flows.
- `POST /api/replay/run-official` — local/offline organizer replay only.

Account endpoints (`/api/auth/signup`, `/api/auth/login`, `/api/auth/me`) have been removed and return 404.

## Release readiness

Before calling the hosted application complete, verify the production alias, frontend build, health/model endpoints, public analysis and replay endpoints, and a browser walkthrough. A Vercel READY deployment proves deployment state only—not model readiness, full replay success, durable hosted history, or official organizer acceptance.

Use `docs/evaluation.md` for training/evaluation/replay reproduction and `docs/release-hardening.md` for causal replay and submission CSV invariants.
