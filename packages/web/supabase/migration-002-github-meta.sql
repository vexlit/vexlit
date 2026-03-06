-- Migration 002: Add github_meta column for deferred GitHub file fetching
-- Run this in Supabase SQL Editor

ALTER TABLE scans ADD COLUMN IF NOT EXISTS github_meta jsonb;

-- Reload PostgREST schema cache so the new column is recognized immediately
NOTIFY pgrst, 'reload schema';
