# Supabase integration

CyberSentinel uses the shared Supabase project `common 1` for Auth and Postgres audit metadata. Its application tables live only in the dedicated `cybersentinel` schema. Existing `bharatsim`, `genomeguard`, and `public` objects are not modified. Network-flow CSVs, raw flow feature payloads, trained model files, and hidden replay inputs remain outside Postgres.

## Runtime configuration

Set these Vercel environment variables for Production, Preview and Development:

- `VITE_SUPABASE_URL`: the `common 1` project URL used by the browser Auth client.
- `VITE_SUPABASE_ANON_KEY`: the `common 1` publishable key (the variable name is retained for compatibility; the value may use the `sb_publishable_` format).
- `SUPABASE_URL`: optional backend alias. If omitted, the Python API falls back to `VITE_SUPABASE_URL`.
- `SUPABASE_ANON_KEY`: optional backend alias. If omitted, the Python API falls back to `VITE_SUPABASE_ANON_KEY`.

The API derives its HTTPS host from the configured URL; it is not pinned to a project ref. The browser key is public by design. RLS and the authenticated user's JWT enforce row ownership. Do not put a Supabase secret/service-role key in a `VITE_` or `NEXT_PUBLIC_` variable. The API forwards the user's bearer token to Supabase Auth and resolves the user before writing.

## Shared-project isolation

All CyberSentinel PostgREST reads and writes explicitly select the `cybersentinel` schema using `Accept-Profile` and `Content-Profile` headers. The schema is added to the PostgREST exposed-schema configuration without removing the existing `public`, `graphql_public`, or `storage` schemas.

The shared project's existing schemas are preserved:

- `bharatsim`: existing BharatSim tables and data.
- `genomeguard`: existing GenomeGuard tables and data.
- `public`: existing shared deployment-status object and Supabase-managed public objects.

CyberSentinel does not create tables in `public`, alter the other application schemas, or change the shared Auth users. RLS scopes every CyberSentinel row to `auth.uid() = user_id`.

## Persisted data

All following tables are in `cybersentinel`:

- `agent2_inference_events`: Agent 2 anomaly score, flag, model metadata and derived evidence.
- `flow_analysis_events`: single-flow, batch, fusion and policy-simulation outcomes.
- `replay_runs`: per-user replay summaries and run metadata.
- `replay_decisions`: per-record predicted class, anomaly index, evidence status and ALLOW/BLOCK result.
- `replay_policies`: per-run adaptive policy scope and activation/expiry record IDs.
- `replay_correlation_groups`: Agent 4 correlation groups, observed record membership and supporting evidence for each replay run.
- `analysis_runs`: evaluation-run summary metadata.

Raw network-flow rows and challenge datasets are never uploaded. The browser/authenticated role receives only SELECT and INSERT privileges; RLS limits both to the caller's own rows. No anonymous table privileges are granted. Table and sequence defaults in this schema were probed and do not grant API-role access. PostgreSQL's global default grants EXECUTE on newly created functions to PUBLIC; a schema-level default revoke cannot override that global grant. CyberSentinel currently creates no database functions, and the shared project's global function defaults are deliberately left unchanged to avoid affecting BharatSim or GenomeGuard. If a function is added to this schema, its migration must explicitly run `REVOKE EXECUTE ON FUNCTION schema.function_name(args) FROM PUBLIC, anon, authenticated, service_role` after creation and add a privilege regression test.

## Migration history

The shared-project bootstrap is kept separate from Supabase's global migration history because that ledger is already used by other applications in `common 1`.

- Canonical shared-schema migration: `database/cybersentinel/001_init.sql`.
- Project-local ledger: `cybersentinel.schema_migrations`.
- Current version: `20261115120000`.

The older `supabase/migrations/` files describe the retired, dedicated `jai-hack` project schema and remain as historical migration records. Do not apply those public-schema migrations to `common 1`; use the isolated `database/cybersentinel/` migration instead.

## Smoke-test checklist

1. Sign in through the Supabase Auth gate on `common 1`.
2. Run Agent 2 independent scoring and verify an `agent2_inference_events` row in `cybersentinel` for the signed-in user.
3. Run single-flow and batch analysis and verify `cybersentinel.flow_analysis_events`.
4. Run chronological replay and verify `cybersentinel.replay_runs`, `replay_decisions`, `replay_policies`, and `replay_correlation_groups`.
5. Sign in as a second user and verify that the first user's rows are not visible.
6. Confirm unauthenticated requests to operational API routes receive HTTP 401.
7. Confirm the existing `bharatsim`, `genomeguard`, and `public.genomeguard_deployment_status` objects remain unchanged.

A successful build alone does not complete this smoke test. The deployed app must be exercised with real authenticated sessions and the organizer's real replay input.

## Evaluation snapshots

The Model Intelligence view can save a compact evaluation snapshot to `cybersentinel.analysis_runs`. It stores metrics and report metadata only; evaluation CSVs and hidden replay data are not uploaded. The Audit History view shows replay runs and evaluation snapshots separately.

## Database performance

The user ownership foreign key on `cybersentinel.agent2_inference_events.user_id` is indexed to keep per-user audit reads and cascading deletes efficient.
