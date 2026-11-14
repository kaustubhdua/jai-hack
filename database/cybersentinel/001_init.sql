-- CyberSentinel schema for the shared Supabase "common 1" project.
-- This is intentionally isolated from the existing bharatsim, genomeguard,
-- and public schemas. Raw network flows and model artifacts are never stored.

BEGIN;

CREATE SCHEMA IF NOT EXISTS cybersentinel;
REVOKE ALL ON SCHEMA cybersentinel FROM PUBLIC, anon;
GRANT USAGE ON SCHEMA cybersentinel TO authenticated;

-- Keep a project-local migration ledger instead of mixing CyberSentinel
-- versions into the shared Supabase migration history.
CREATE TABLE IF NOT EXISTS cybersentinel.schema_migrations (
    version text PRIMARY KEY,
    name text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE cybersentinel.schema_migrations ENABLE ROW LEVEL SECURITY;
REVOKE ALL PRIVILEGES ON TABLE cybersentinel.schema_migrations FROM PUBLIC, anon, authenticated, service_role;

-- Future objects in this isolated schema are private unless explicitly granted.
ALTER DEFAULT PRIVILEGES IN SCHEMA cybersentinel
  REVOKE ALL PRIVILEGES ON TABLES FROM PUBLIC, anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA cybersentinel
  REVOKE ALL PRIVILEGES ON SEQUENCES FROM PUBLIC, anon, authenticated, service_role;
ALTER DEFAULT PRIVILEGES IN SCHEMA cybersentinel
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC, anon, authenticated, service_role;

CREATE TABLE cybersentinel.analysis_runs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    dataset_name text NOT NULL,
    dataset_rows bigint NOT NULL DEFAULT 0 CHECK (dataset_rows >= 0),
    processed_rows bigint NOT NULL DEFAULT 0 CHECK (processed_rows >= 0),
    status text NOT NULL DEFAULT 'completed'
        CHECK (status IN ('queued', 'running', 'completed', 'failed')),
    model_version text,
    accuracy double precision
        CHECK (accuracy IS NULL OR (accuracy >= 0 AND accuracy <= 1)),
    macro_f1 double precision
        CHECK (macro_f1 IS NULL OR (macro_f1 >= 0 AND macro_f1 <= 1)),
    summary jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX analysis_runs_user_created_idx
    ON cybersentinel.analysis_runs (user_id, created_at DESC);
ALTER TABLE cybersentinel.analysis_runs ENABLE ROW LEVEL SECURITY;
CREATE POLICY analysis_runs_user_select ON cybersentinel.analysis_runs
    FOR SELECT TO authenticated USING ((SELECT auth.uid()) = user_id);
CREATE POLICY analysis_runs_user_insert ON cybersentinel.analysis_runs
    FOR INSERT TO authenticated WITH CHECK ((SELECT auth.uid()) = user_id);

CREATE TABLE cybersentinel.agent2_inference_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    source text NOT NULL CHECK (source IN ('agent2_independent', 'pipeline_analysis')),
    model_version text NOT NULL DEFAULT 'agent2-isolation-forest',
    anomaly_score double precision NOT NULL
        CHECK (anomaly_score >= 0 AND anomaly_score <= 1),
    is_anomaly boolean NOT NULL,
    feature_count integer NOT NULL DEFAULT 0 CHECK (feature_count >= 0),
    evidence jsonb NOT NULL DEFAULT '[]'::jsonb,
    request_metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX agent2_inference_events_created_at_idx
    ON cybersentinel.agent2_inference_events (created_at DESC);
CREATE INDEX agent2_inference_events_user_id_idx
    ON cybersentinel.agent2_inference_events (user_id);
ALTER TABLE cybersentinel.agent2_inference_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY agent2_events_user_select ON cybersentinel.agent2_inference_events
    FOR SELECT TO authenticated USING ((SELECT auth.uid()) = user_id);
CREATE POLICY agent2_events_user_insert ON cybersentinel.agent2_inference_events
    FOR INSERT TO authenticated WITH CHECK ((SELECT auth.uid()) = user_id);

CREATE TABLE cybersentinel.replay_runs (
    run_id text PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    dataset_name text NOT NULL,
    total_records bigint NOT NULL DEFAULT 0 CHECK (total_records >= 0),
    blocked_records bigint NOT NULL DEFAULT 0 CHECK (blocked_records >= 0),
    allowed_records bigint NOT NULL DEFAULT 0 CHECK (allowed_records >= 0),
    policies_created bigint NOT NULL DEFAULT 0 CHECK (policies_created >= 0),
    containment_rate double precision
        CHECK (containment_rate IS NULL OR containment_rate BETWEEN 0 AND 100),
    throughput_fps double precision
        CHECK (throughput_fps IS NULL OR throughput_fps >= 0),
    elapsed_seconds double precision
        CHECK (elapsed_seconds IS NULL OR elapsed_seconds >= 0),
    status text NOT NULL CHECK (status IN ('COMPLETED','VALIDATION_FAILED','FAILED')),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX replay_runs_user_created_idx
    ON cybersentinel.replay_runs (user_id, created_at DESC);
ALTER TABLE cybersentinel.replay_runs ENABLE ROW LEVEL SECURITY;
CREATE POLICY replay_runs_user_select ON cybersentinel.replay_runs
    FOR SELECT TO authenticated USING ((SELECT auth.uid()) = user_id);
CREATE POLICY replay_runs_user_insert ON cybersentinel.replay_runs
    FOR INSERT TO authenticated WITH CHECK ((SELECT auth.uid()) = user_id);

CREATE TABLE cybersentinel.flow_analysis_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    source text NOT NULL CHECK (source IN ('single_flow','batch_replay','fusion_simulation','policy_simulation')),
    record_id text,
    predicted_class text,
    anomaly_score double precision
        CHECK (anomaly_score IS NULL OR anomaly_score BETWEEN 0 AND 1),
    is_anomaly boolean,
    final_class text,
    evidence_status text,
    action text CHECK (action IS NULL OR action IN ('ALLOW','BLOCK','REVIEW')),
    rationale jsonb NOT NULL DEFAULT '[]'::jsonb,
    latency_ms double precision CHECK (latency_ms IS NULL OR latency_ms >= 0)
);
CREATE INDEX flow_analysis_events_user_created_idx
    ON cybersentinel.flow_analysis_events (user_id, created_at DESC);
ALTER TABLE cybersentinel.flow_analysis_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY flow_events_user_select ON cybersentinel.flow_analysis_events
    FOR SELECT TO authenticated USING ((SELECT auth.uid()) = user_id);
CREATE POLICY flow_events_user_insert ON cybersentinel.flow_analysis_events
    FOR INSERT TO authenticated WITH CHECK ((SELECT auth.uid()) = user_id);

CREATE TABLE cybersentinel.replay_decisions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    run_id text NOT NULL REFERENCES cybersentinel.replay_runs(run_id) ON DELETE CASCADE,
    record_id text NOT NULL,
    seq bigint NOT NULL CHECK (seq > 0),
    predicted_class text NOT NULL,
    anomaly_score double precision NOT NULL CHECK (anomaly_score BETWEEN 0 AND 1),
    evidence_status text NOT NULL CHECK (evidence_status IN ('AGREE','CONFLICT','UNCERTAIN')),
    action text NOT NULL CHECK (action IN ('ALLOW','BLOCK')),
    active_policy_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (run_id, record_id)
);
CREATE INDEX replay_decisions_user_run_seq_idx
    ON cybersentinel.replay_decisions (user_id, run_id, seq);
ALTER TABLE cybersentinel.replay_decisions ENABLE ROW LEVEL SECURITY;
CREATE POLICY replay_decisions_user_select ON cybersentinel.replay_decisions
    FOR SELECT TO authenticated USING ((SELECT auth.uid()) = user_id);
CREATE POLICY replay_decisions_user_insert ON cybersentinel.replay_decisions
    FOR INSERT TO authenticated WITH CHECK ((SELECT auth.uid()) = user_id);

CREATE TABLE cybersentinel.replay_policies (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    run_id text NOT NULL REFERENCES cybersentinel.replay_runs(run_id) ON DELETE CASCADE,
    policy_id text NOT NULL,
    activated_after_record_id text NOT NULL,
    scope_type text NOT NULL CHECK (scope_type IN ('SOURCE_IP','DESTINATION_IP','SRC_DST_PAIR')),
    scope_value text NOT NULL,
    expires_after_record_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (run_id, policy_id)
);
CREATE INDEX replay_policies_user_run_idx
    ON cybersentinel.replay_policies (user_id, run_id);
ALTER TABLE cybersentinel.replay_policies ENABLE ROW LEVEL SECURITY;
CREATE POLICY replay_policies_user_select ON cybersentinel.replay_policies
    FOR SELECT TO authenticated USING ((SELECT auth.uid()) = user_id);
CREATE POLICY replay_policies_user_insert ON cybersentinel.replay_policies
    FOR INSERT TO authenticated WITH CHECK ((SELECT auth.uid()) = user_id);

CREATE TABLE cybersentinel.replay_correlation_groups (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    run_id text NOT NULL REFERENCES cybersentinel.replay_runs(run_id) ON DELETE CASCADE,
    group_id text NOT NULL,
    attack_type text NOT NULL,
    source_identity text,
    target_endpoints jsonb NOT NULL DEFAULT '[]'::jsonb,
    member_record_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    flow_count bigint NOT NULL CHECK (flow_count >= 0),
    start_record_id text,
    end_record_id text,
    confidence double precision CHECK (confidence IS NULL OR confidence BETWEEN 0 AND 1),
    evidence jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (run_id, group_id)
);
CREATE INDEX replay_correlation_groups_user_run_idx
    ON cybersentinel.replay_correlation_groups (user_id, run_id, created_at DESC);
ALTER TABLE cybersentinel.replay_correlation_groups ENABLE ROW LEVEL SECURITY;
CREATE POLICY replay_groups_user_select ON cybersentinel.replay_correlation_groups
    FOR SELECT TO authenticated USING ((SELECT auth.uid()) = user_id);
CREATE POLICY replay_groups_user_insert ON cybersentinel.replay_correlation_groups
    FOR INSERT TO authenticated WITH CHECK ((SELECT auth.uid()) = user_id);

-- Explicit least-privilege grants for browser/API users.
REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA cybersentinel FROM PUBLIC, anon, authenticated, service_role;
GRANT SELECT, INSERT ON TABLE
    cybersentinel.analysis_runs,
    cybersentinel.agent2_inference_events,
    cybersentinel.replay_runs,
    cybersentinel.flow_analysis_events,
    cybersentinel.replay_decisions,
    cybersentinel.replay_policies,
    cybersentinel.replay_correlation_groups
TO authenticated;

-- Add the isolated schema to PostgREST without removing existing schemas.
ALTER ROLE authenticator SET pgrst.db_schemas = 'public, graphql_public, storage, cybersentinel';
NOTIFY pgrst, 'reload config';
NOTIFY pgrst, 'reload schema';

INSERT INTO cybersentinel.schema_migrations (version, name)
VALUES ('20261115120000', 'cybersentinel_shared_schema_init')
ON CONFLICT (version) DO NOTHING;

COMMIT;
