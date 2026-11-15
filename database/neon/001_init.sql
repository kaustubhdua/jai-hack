-- CyberSentinel Neon Postgres schema. Safe to apply more than once.
CREATE SCHEMA IF NOT EXISTS cybersentinel;

CREATE TABLE IF NOT EXISTS cybersentinel.users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    is_active boolean NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS cybersentinel.replay_runs (
    run_id text NOT NULL,
    user_id uuid NOT NULL REFERENCES cybersentinel.users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    dataset_name text NOT NULL,
    total_records bigint NOT NULL DEFAULT 0 CHECK (total_records >= 0),
    blocked_records bigint NOT NULL DEFAULT 0 CHECK (blocked_records >= 0),
    allowed_records bigint NOT NULL DEFAULT 0 CHECK (allowed_records >= 0),
    policies_created bigint NOT NULL DEFAULT 0 CHECK (policies_created >= 0),
    containment_rate double precision,
    throughput_fps double precision,
    elapsed_seconds double precision,
    status text NOT NULL CHECK (status IN ('COMPLETED', 'VALIDATION_FAILED', 'FAILED')),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (run_id, user_id)
);
CREATE INDEX IF NOT EXISTS replay_runs_user_created_idx
    ON cybersentinel.replay_runs(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS cybersentinel.audit_events (
    id bigserial PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES cybersentinel.users(id) ON DELETE CASCADE,
    event_type text NOT NULL CHECK (event_type IN (
        'agent2_inference_events', 'flow_analysis_events', 'replay_decisions',
        'replay_policies', 'replay_correlation_groups', 'analysis_runs'
    )),
    run_id text,
    created_at timestamptz NOT NULL DEFAULT now(),
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    FOREIGN KEY (run_id, user_id)
        REFERENCES cybersentinel.replay_runs(run_id, user_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS audit_events_user_type_created_idx
    ON cybersentinel.audit_events(user_id, event_type, created_at DESC);
CREATE INDEX IF NOT EXISTS audit_events_user_run_idx
    ON cybersentinel.audit_events(user_id, run_id, created_at DESC);

CREATE TABLE IF NOT EXISTS cybersentinel.auth_rate_limits (
    id bigserial PRIMARY KEY,
    email_hash text NOT NULL,
    attempted_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS auth_rate_limits_email_time_idx
    ON cybersentinel.auth_rate_limits(email_hash, attempted_at DESC);

CREATE TABLE IF NOT EXISTS cybersentinel.schema_migrations (
    version text PRIMARY KEY,
    name text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO cybersentinel.schema_migrations(version, name)
VALUES ('20261115030000', 'neon_backend_auth_and_audit_schema')
ON CONFLICT (version) DO NOTHING;
