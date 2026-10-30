-- CyberSentinel Supabase Schema & Row-Level Security (RLS)
-- Enables authenticated user history, audit runs, and model evaluation telemetry

-- Enable UUID extension
create extension if not exists "uuid-ossp";

-- Table: analysis_runs
-- Stores user-specific dataset audit & flow analysis runs
create table if not exists public.analysis_runs (
    id uuid primary key default gen_random_uuid(),
    user_id uuid references auth.users(id) on delete cascade not null default auth.uid(),
    dataset_name text not null,
    dataset_rows integer not null default 0,
    processed_rows integer not null default 0,
    status text not null check (status in ('pending', 'processing', 'completed', 'failed')),
    accuracy numeric,
    macro_f1 numeric,
    benign_fpr numeric,
    actions_summary jsonb default '{"ALLOW": 0, "BLOCK": 0, "REVIEW": 0}'::jsonb,
    metadata jsonb default '{}'::jsonb,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

-- Table: flow_events (ephemeral/aggregated security findings, no raw PII/packet data)
create table if not exists public.flow_events (
    id uuid primary key default gen_random_uuid(),
    run_id uuid references public.analysis_runs(id) on delete cascade,
    user_id uuid references auth.users(id) on delete cascade not null default auth.uid(),
    predicted_class text not null,
    confidence numeric not null,
    anomaly_score numeric,
    is_anomaly boolean,
    evidence_status text not null,
    action text not null check (action in ('ALLOW', 'BLOCK', 'REVIEW')),
    rationale text[],
    supporting_evidence text[],
    created_at timestamptz not null default now()
);

-- Indices for performance
create index if not exists idx_analysis_runs_user_id on public.analysis_runs(user_id);
create index if not exists idx_analysis_runs_created_at on public.analysis_runs(created_at desc);
create index if not exists idx_flow_events_run_id on public.flow_events(run_id);
create index if not exists idx_flow_events_user_id on public.flow_events(user_id);

-- Enable Row Level Security (RLS)
alter table public.analysis_runs enable row level security;
alter table public.flow_events enable row level security;

-- RLS Policies for analysis_runs: users access ONLY their own records
drop policy if exists "Users can view their own analysis runs" on public.analysis_runs;
create policy "Users can view their own analysis runs"
    on public.analysis_runs
    for select
    using (auth.uid() = user_id);

drop policy if exists "Users can insert their own analysis runs" on public.analysis_runs;
create policy "Users can insert their own analysis runs"
    on public.analysis_runs
    for insert
    with check (auth.uid() = user_id);

drop policy if exists "Users can update their own analysis runs" on public.analysis_runs;
create policy "Users can update their own analysis runs"
    on public.analysis_runs
    for update
    using (auth.uid() = user_id);

drop policy if exists "Users can delete their own analysis runs" on public.analysis_runs;
create policy "Users can delete their own analysis runs"
    on public.analysis_runs
    for delete
    using (auth.uid() = user_id);

-- RLS Policies for flow_events
drop policy if exists "Users can view their own flow events" on public.flow_events;
create policy "Users can view their own flow events"
    on public.flow_events
    for select
    using (auth.uid() = user_id);

drop policy if exists "Users can insert their own flow events" on public.flow_events;
create policy "Users can insert their own flow events"
    on public.flow_events
    for insert
    with check (auth.uid() = user_id);
