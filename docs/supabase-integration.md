# Supabase integration

CyberSentinel uses Supabase Auth and Postgres for user-scoped audit metadata. Network-flow CSVs and raw flow feature payloads remain in the local replay workspace; they are not uploaded to Supabase.

## Runtime configuration

Set these Vercel environment variables for Production, Preview and Development:

- `VITE_SUPABASE_URL`: the Supabase project URL.
- `VITE_SUPABASE_ANON_KEY`: the project's publishable key (the variable name is retained for compatibility; the value may use the `sb_publishable_` format).

The publishable key is public by design. RLS and the authenticated user's JWT enforce data ownership. Do not put a Supabase secret/service-role key in a `VITE_` or `NEXT_PUBLIC_` variable. The API forwards the user's bearer token to Supabase and resolves the user through Auth before writing.

## Persisted data

- `agent2_inference_events`: Agent 2 anomaly score, flag, model metadata and derived evidence.
- `flow_analysis_events`: single-flow, batch, fusion and policy-simulation outcomes.
- `replay_runs`: per-user replay summaries and run metadata.
- `replay_decisions`: per-record predicted class, anomaly index, evidence status and ALLOW/BLOCK result.
- `replay_policies`: per-run adaptive policy scope and activation/expiry record IDs.
- `analysis_runs`: evaluation-run summary schema retained for the evaluation workflow.

All user-owned tables use RLS with `auth.uid() = user_id`. The browser can only read and insert its own rows. The server verifies the bearer token with Supabase Auth; client-supplied user IDs are never trusted.

## Migration history

The live Supabase project records the following versions. The corresponding versioned files are the canonical migrations:

- `20261031073431_add_user_scoped_cybersentinel_audit.sql`
- `20261031074022_tighten_user_audit_table_grants.sql`
- `20261031074154_persist_replay_decisions_policies_and_simulation_events.sql
- `20261031074806_tighten_analysis_run_snapshot_permissions.sql``

Earlier timestamp-named placeholder files are retained as no-ops so older checkouts do not replay already-applied schema changes.

## Smoke-test checklist

1. Sign in through the Supabase Auth gate.
2. Run Agent 2 independent scoring and verify an `agent2_inference_events` row for the signed-in user.
3. Run single-flow and batch analysis and verify `flow_analysis_events`.
4. Run chronological replay and verify `replay_runs`, `replay_decisions` and `replay_policies`.
5. Sign in as another user and verify that the first user's rows are not visible.
6. Confirm unauthenticated requests to operational API routes receive HTTP 401.

A successful build alone does not complete this smoke test. The deployed app must be exercised with a real authenticated session and the organizer's real replay input.

## Evaluation snapshots
The Model Intelligence view can save a compact evaluation snapshot to `analysis_runs`. It stores metrics and report metadata only; evaluation CSVs and hidden replay data are not uploaded. The Audit History view shows replay runs and evaluation snapshots separately.
