-- Phase 4: Reachable Vuln + Policy Engine
-- Run in Supabase SQL Editor, then: NOTIFY pgrst, 'reload schema';

-- 1. Add reachable flag to vulnerabilities
ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS reachable boolean DEFAULT NULL;

-- 2. Add policy_status to scans
ALTER TABLE scans ADD COLUMN IF NOT EXISTS policy_status text DEFAULT NULL;

-- 3. Policies table
CREATE TABLE IF NOT EXISTS policies (
  id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  project_id uuid REFERENCES projects(id) ON DELETE CASCADE,
  name text NOT NULL,
  description text DEFAULT '',
  enabled boolean DEFAULT true,
  conditions jsonb NOT NULL DEFAULT '{}',
  action text NOT NULL DEFAULT 'warn',
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

ALTER TABLE policies ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users manage own policies"
  ON policies FOR ALL
  USING (auth.uid() = user_id);

-- 4. Policy evaluations per scan
CREATE TABLE IF NOT EXISTS policy_evaluations (
  id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
  scan_id uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  policy_id uuid NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
  status text NOT NULL,
  matched_count integer DEFAULT 0,
  details jsonb DEFAULT '[]',
  created_at timestamptz DEFAULT now()
);

ALTER TABLE policy_evaluations ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users view own evaluations"
  ON policy_evaluations FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM scans s
      JOIN projects p ON s.project_id = p.id
      WHERE s.id = policy_evaluations.scan_id
      AND p.user_id = auth.uid()
    )
  );

-- Index for fast policy lookup
CREATE INDEX IF NOT EXISTS idx_policies_user_id ON policies(user_id);
CREATE INDEX IF NOT EXISTS idx_policies_project_id ON policies(project_id);
CREATE INDEX IF NOT EXISTS idx_policy_evaluations_scan_id ON policy_evaluations(scan_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_reachable ON vulnerabilities(scan_id, reachable) WHERE reachable IS NOT NULL;

NOTIFY pgrst, 'reload schema';
