-- Migration 003: Add ai_cache table for caching AI responses
-- Run this in Supabase SQL Editor

CREATE TABLE IF NOT EXISTS ai_cache (
  id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
  cache_key text UNIQUE NOT NULL,
  response text NOT NULL,
  created_at timestamptz DEFAULT now()
);

-- Index for fast lookups
CREATE INDEX IF NOT EXISTS idx_ai_cache_key ON ai_cache(cache_key);

-- Reload PostgREST schema cache
NOTIFY pgrst, 'reload schema';
