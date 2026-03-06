-- Migration 001: Add file_contents column for queue worker pattern
-- Run this in Supabase SQL Editor

ALTER TABLE scans ADD COLUMN IF NOT EXISTS file_contents jsonb;
