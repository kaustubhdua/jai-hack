ALTER TABLE public.flow_analysis_events
  DROP CONSTRAINT IF EXISTS flow_analysis_events_source_check;
ALTER TABLE public.flow_analysis_events
  ADD CONSTRAINT flow_analysis_events_source_check
  CHECK (source IN ('single_flow','batch_replay','fusion_simulation','policy_simulation'));

CREATE TABLE public.replay_decisions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  run_id text NOT NULL REFERENCES public.replay_runs(run_id) ON DELETE CASCADE,
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
CREATE INDEX replay_decisions_user_run_seq_idx ON public.replay_decisions (user_id, run_id, seq);
ALTER TABLE public.replay_decisions ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can insert their own replay decisions" ON public.replay_decisions
  FOR INSERT TO authenticated WITH CHECK ((SELECT auth.uid()) = user_id);
CREATE POLICY "Users can read their own replay decisions" ON public.replay_decisions
  FOR SELECT TO authenticated USING ((SELECT auth.uid()) = user_id);
REVOKE ALL PRIVILEGES ON public.replay_decisions FROM anon, authenticated;
GRANT SELECT, INSERT ON public.replay_decisions TO authenticated;

CREATE TABLE public.replay_policies (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  run_id text NOT NULL REFERENCES public.replay_runs(run_id) ON DELETE CASCADE,
  policy_id text NOT NULL,
  activated_after_record_id text NOT NULL,
  scope_type text NOT NULL CHECK (scope_type IN ('SOURCE_IP','DESTINATION_IP','SRC_DST_PAIR')),
  scope_value text NOT NULL,
  expires_after_record_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (run_id, policy_id)
);
CREATE INDEX replay_policies_user_run_idx ON public.replay_policies (user_id, run_id);
ALTER TABLE public.replay_policies ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can insert their own replay policies" ON public.replay_policies
  FOR INSERT TO authenticated WITH CHECK ((SELECT auth.uid()) = user_id);
CREATE POLICY "Users can read their own replay policies" ON public.replay_policies
  FOR SELECT TO authenticated USING ((SELECT auth.uid()) = user_id);
REVOKE ALL PRIVILEGES ON public.replay_policies FROM anon, authenticated;
GRANT SELECT, INSERT ON public.replay_policies TO authenticated;
