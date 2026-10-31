REVOKE ALL PRIVILEGES ON TABLE public.replay_runs FROM anon, authenticated;
GRANT SELECT, INSERT ON TABLE public.replay_runs TO authenticated;
REVOKE ALL PRIVILEGES ON TABLE public.flow_analysis_events FROM anon, authenticated;
GRANT SELECT, INSERT ON TABLE public.flow_analysis_events TO authenticated;
