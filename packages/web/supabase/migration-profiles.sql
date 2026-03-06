-- VEXLIT: profiles table + notifications table migration
-- Run this in Supabase SQL Editor

-- Profiles table (extends auth.users)
create table if not exists profiles (
  id uuid references auth.users(id) on delete cascade primary key,
  terms_version text,
  terms_accepted_at timestamptz,
  terms_ip text,
  marketing_consent boolean default false,
  repo_scope text default 'public_only' check (repo_scope in ('public_only', 'all')),
  feature_pr_check boolean default true,
  feature_auto_fix_pr boolean default true,
  feature_dep_upgrade boolean default true,
  feature_code_analysis boolean default true,
  created_at timestamptz default now() not null,
  updated_at timestamptz default now() not null
);

-- Notifications table
create table if not exists notifications (
  id uuid default gen_random_uuid() primary key,
  user_id uuid references auth.users(id) on delete cascade not null,
  type text not null,
  title text not null,
  message text,
  link text,
  read_at timestamptz,
  created_at timestamptz default now() not null
);

-- Indexes
create index if not exists idx_profiles_terms on profiles(terms_accepted_at);
create index if not exists idx_notifications_user_id on notifications(user_id);
create index if not exists idx_notifications_read on notifications(user_id, read_at);

-- RLS
alter table profiles enable row level security;
alter table notifications enable row level security;

-- Profiles policies
create policy "Users can view own profile"
  on profiles for select using (auth.uid() = id);
create policy "Users can insert own profile"
  on profiles for insert with check (auth.uid() = id);
create policy "Users can update own profile"
  on profiles for update using (auth.uid() = id);

-- Notifications policies
create policy "Users can view own notifications"
  on notifications for select using (auth.uid() = user_id);
create policy "Users can update own notifications"
  on notifications for update using (auth.uid() = user_id);

-- Reload PostgREST schema cache
NOTIFY pgrst, 'reload schema';
