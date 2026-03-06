-- Add confidence column to vulnerabilities table
alter table vulnerabilities
  add column if not exists confidence text not null default 'medium'
  check (confidence in ('high', 'medium', 'low'));
