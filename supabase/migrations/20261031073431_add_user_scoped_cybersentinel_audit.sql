-- User-scoped cloud audit. Raw flow payloads and CSVs stay local.
ALTER TABLE public.agent2_inference_events
  ADD COLUMN user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE;
CREATE POLICY "Users can insert their own Agent 2 events" ON public.agent2_inference_events
  FOR INSERT TO authenticated WITH CHECK ((SELECT auth.uid()) = user_id);
CREATE POLICY "Users can read their own Agent 2 events" ON public.agent2_inference_events
  FOR SELECT TO authenticated USING ((SELECT auth.uid()) = user_id);
GRANT SELECT, INSERT ON public.agent2_inference_events TO authenticated;
REVOKE ALL PRIVILEGES ON public.agent2_inference_events FROM anon;

CREATE TABLE public.replay_runs (
  run_id text PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  dataset_name text NOT NULL,
  total_records bigint NOT NULL DEFAULT 0 CHECK (total_records >= 0),
  blocked_records bigint NOT NULL DEFAULT 0 CHECK (blocked_records >= 0),
  allowed_records bigint NOT NULL DEFAULT 0 CHECK (allowed_records >= 0),
  policies_created bigint NOT NULL DEFAULT 0 CHECK (policies_created >= 0),
  containment_rate double precision CHECK (containment_rate IS NULL OR containment_rate BETWEEN 0 AND 100),
  throughput_fps double precision CHECK (throughput_fps IS NULL OR throughput_fps >= 0),
  elapsed_seconds double precision CHECK (elapsed_seconds IS NULL OR elapsed_seconds >= 0),
  status text NOT NULL CHECK (status IN ('COMPLETED','VALIDATION_FAILED','FAILED')),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX replay_runs_user_created_idx ON public.replay_runs (user_id, created_at DESC);
ALTER TABLE public.replay_runs ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can create their own replay runs" ON public.replay_runs
  FOR INSERT TO authenticated WITH CHECK ((SELECT auth.uid()) = user_id);
CREATE POLICY "Users can read their own replay runs" ON public.replay_runs
  FOR SELECT TO authenticated USING ((SELECT auth.uid()) = user_id);
GRANT SELECT, INSERT ON public.replay_runs TO authenticated;
REVOKE ALL PRIVILEGES ON public.replay_runs FROM anon, authenticated;
GRANT SELECT, INSERT ON public.replay_runs TO authenticated;

CREATE TABLE public.flow_analysis_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  source text NOT NULL CHECK (source IN ('single_flow','batch_replay')),
  record_id text,
  predicted_class text,
  anomaly_score double precision CHECK (anomaly_score IS NULL OR anomaly_score BETWEEN 0 AND 1),
  is_anomaly boolean,
  final_class text,
  evidence_status text,
  action text CHECK (action IS NULL OR action IN ('ALLOW','BLOCK','REVIEW')),
  rationale jsonb NOT NULL DEFAULT '[]'::jsonb,
  latency_ms double precision CHECK (latency_ms IS NULL OR latency_ms >= 0)
);
CREATE INDEX flow_analysis_events_user_created_idx ON public.flow_analysis_events (user_id, created_at DESC);
ALTER TABLE public.flow_analysis_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can insert their own flow analysis events" ON public.flow_analysis_events
  FOR INSERT TO authenticated WITH CHECK ((SELECT auth.uid()) = user_id);
CREATE POLICY "Users can read their own flow analysis events" ON public.flow_analysis_events
  FOR SELECT TO authenticated USING ((SELECT auth.uid()) = user_id);
REVOKE ALL PRIVILEGES ON public.flow_analysis_events FROM anon, authenticated;
GRANT SELECT, INSERT ON public.flow_analysis_events TO authenticated;
