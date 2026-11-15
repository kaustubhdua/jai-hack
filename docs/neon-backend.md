# CyberSentinel backend (no Supabase)

CyberSentinel uses Neon Postgres as its only hosted database and the FastAPI application as its authentication boundary. Supabase Auth, PostgREST, RLS, client SDKs, URLs, and keys are not part of the runtime.

## Architecture

- React calls the same-origin /api/* FastAPI routes.
- The browser stores a short-lived bearer token and sends it only to the CyberSentinel API.
- FastAPI verifies an HMAC-SHA256 token using server-only AUTH_SECRET; it resolves the account from cybersentinel.users.
- Passwords are salted and hashed with PBKDF2-HMAC-SHA256 (600,000 iterations). Passwords are never stored in plaintext.
- Neon Postgres stores account records, replay summaries, and derived audit events. The API derives user_id from the verified token; client-supplied tenant IDs are ignored.
- Replay decisions, policies, and correlation groups have a composite tenant/run foreign key. Reads always filter by the authenticated user.
- Raw flow datasets and trained model artifacts are not uploaded into Postgres.

## Required server environment

Set these as sensitive Vercel variables for Production, Preview, and Development:

- DATABASE_URL: Neon pooled Postgres connection string for the cybersentinel database. Use the restricted cybersentinel_app role, not the database owner.
- AUTH_SECRET: random server-only secret of at least 32 characters used to sign session tokens.

Never expose either value through a VITE_ variable. The browser needs no database key or provider SDK.

## Database objects

All objects are isolated in the cybersentinel schema:

- users: normalized unique email, salted password hash, active flag, creation time.
- replay_runs: per-user replay summary and run metadata; primary key (run_id,user_id).
- audit_events: derived inference, replay-decision, policy, correlation, and evaluation metadata. A composite FK ties replay child events to the same user's replay run.
- auth_rate_limits: reserved for login throttling telemetry.
- schema_migrations: project-local schema version.

The database role used by Vercel is restricted to this schema. The database is a separate Neon project and does not share tables or credentials with GenomeGuard, BharatSim, RideForge, or other applications.

## Account API

- POST /api/auth/signup — create an account and return a bearer token.
- POST /api/auth/login — verify credentials and return a bearer token.
- GET /api/auth/me — validate the current token and return the account.
- Signing out clears the browser token. Tokens expire after 12 hours.

This lightweight account system does not send email confirmation or provide password recovery. Do not reuse a sensitive password. Account recovery requires a separately configured email delivery flow.

## Free-tier operations

The Neon project is configured on its free tier with a 0.25 CU compute and scale-to-zero. Cold requests may take longer while the database wakes. Keep audit payloads compact; never store raw flow rows, model files, or uploaded datasets in the database. Monitor free-tier storage, compute-active time, and network transfer in the Neon console.

## Local development

For API routes requiring account persistence, configure DATABASE_URL and AUTH_SECRET in the local environment. Without them, the public read-only demo and local SQLite run history remain available, but private hosted operations fail closed. Never commit local secrets.
