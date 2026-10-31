CREATE TABLE public.replay_correlation_groups (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  run_id text NOT NULL REFERENCES public.replay_runs(run_id) ON DELETE CASCADE,
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
  ON public.replay_correlation_groups (user_id, run_id, created_at DESC);
ALTER TABLE public.replay_correlation_groups ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can insert their own correlation groups" ON public.replay_correlation_groups
  FOR INSERT TO authenticated WITH CHECK ((SELECT auth.uid()) = user_id);
CREATE POLICY "Users can read their own correlation groups" ON public.replay_correlation_groups
  FOR SELECT TO authenticated USING ((SELECT auth.uid()) = user_id);
REVOKE ALL PRIVILEGES ON public.replay_correlation_groups FROM anon, authenticated;
GRANT SELECT, INSERT ON public.replay_correlation_groups TO authenticated;
