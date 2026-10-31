DROP POLICY IF EXISTS "Users can update their own analysis runs" ON public.analysis_runs;
DROP POLICY IF EXISTS "Users can delete their own analysis runs" ON public.analysis_runs;
REVOKE ALL PRIVILEGES ON TABLE public.analysis_runs FROM anon, authenticated;
GRANT SELECT, INSERT ON TABLE public.analysis_runs TO authenticated;
