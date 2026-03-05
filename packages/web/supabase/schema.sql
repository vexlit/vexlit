-- VEXLIT SaaS Database Schema
-- Run this in Supabase SQL Editor

-- Projects table
create table if not exists projects (
  id uuid default gen_random_uuid() primary key,
  user_id uuid references auth.users(id) on delete cascade not null,
  name text not null,
  github_url text,
  description text,
  created_at timestamptz default now() not null,
  updated_at timestamptz default now() not null
);

-- Scans table
create table if not exists scans (
  id uuid default gen_random_uuid() primary key,
  project_id uuid references projects(id) on delete cascade not null,
  status text not null default 'pending' check (status in ('pending', 'running', 'completed', 'failed')),
  commit_sha text,
  branch text,
  total_vulnerabilities int default 0,
  critical_count int default 0,
  warning_count int default 0,
  info_count int default 0,
  duration_ms int,
  sarif_json jsonb,
  error_message text,
  created_at timestamptz default now() not null,
  completed_at timestamptz
);

-- Vulnerabilities table
create table if not exists vulnerabilities (
  id uuid default gen_random_uuid() primary key,
  scan_id uuid references scans(id) on delete cascade not null,
  rule_id text not null,
  rule_name text not null,
  severity text not null check (severity in ('critical', 'warning', 'info')),
  message text not null,
  file_path text not null,
  line int not null,
  "column" int not null default 1,
  snippet text,
  cwe text,
  owasp text,
  suggestion text,
  created_at timestamptz default now() not null
);

-- Indexes
create index if not exists idx_projects_user_id on projects(user_id);
create index if not exists idx_scans_project_id on scans(project_id);
create index if not exists idx_scans_status on scans(status);
create index if not exists idx_scans_created_at on scans(created_at desc);
create index if not exists idx_vulnerabilities_scan_id on vulnerabilities(scan_id);
create index if not exists idx_vulnerabilities_severity on vulnerabilities(severity);

-- Row Level Security
alter table projects enable row level security;
alter table scans enable row level security;
alter table vulnerabilities enable row level security;

-- Policies: users can only access their own data
create policy "Users can view own projects"
  on projects for select
  using (auth.uid() = user_id);

create policy "Users can create projects"
  on projects for insert
  with check (auth.uid() = user_id);

create policy "Users can update own projects"
  on projects for update
  using (auth.uid() = user_id);

create policy "Users can delete own projects"
  on projects for delete
  using (auth.uid() = user_id);

create policy "Users can view own scans"
  on scans for select
  using (project_id in (select id from projects where user_id = auth.uid()));

create policy "Users can create scans"
  on scans for insert
  with check (project_id in (select id from projects where user_id = auth.uid()));

create policy "Users can view own vulnerabilities"
  on vulnerabilities for select
  using (scan_id in (
    select s.id from scans s
    join projects p on s.project_id = p.id
    where p.user_id = auth.uid()
  ));
