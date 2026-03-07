import type { Dependency, Advisory } from "./types.js";

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_URL = "https://api.osv.dev/v1/vulns";
const BATCH_SIZE = 100;
const TIMEOUT_MS = 5_000;
const MAX_RETRIES = 1;
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes
const CACHE_MAX_ENTRIES = 5000;

/** In-memory cache for OSV advisory results keyed by "ecosystem:name@version" */
const osvCache = new Map<string, { advisories: Advisory[]; ts: number }>();

function getCached(key: string): Advisory[] | null {
  const entry = osvCache.get(key);
  if (!entry) return null;
  if (Date.now() - entry.ts > CACHE_TTL_MS) {
    osvCache.delete(key);
    return null;
  }
  return entry.advisories;
}

function setCache(key: string, advisories: Advisory[]): void {
  // Evict oldest entries when cache exceeds max size
  if (osvCache.size >= CACHE_MAX_ENTRIES) {
    const firstKey = osvCache.keys().next().value;
    if (firstKey !== undefined) osvCache.delete(firstKey);
  }
  osvCache.set(key, { advisories, ts: Date.now() });
}

interface OsvQuery {
  package: { name: string; ecosystem: string };
  version: string;
}

interface OsvBatchResult {
  results: { vulns?: { id: string }[] }[];
}

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: { type: string; score: string }[];
  affected?: {
    ranges?: { events?: { fixed?: string }[] }[];
    versions?: string[];
  }[];
  references?: { type: string; url: string }[];
  database_specific?: { severity?: string };
}

/** Fetch with timeout and retry */
async function fetchWithTimeout(
  url: string,
  init: RequestInit,
  timeoutMs = TIMEOUT_MS
): Promise<Response> {
  let lastError: unknown;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, { ...init, signal: controller.signal });
      clearTimeout(timer);
      return res;
    } catch (err) {
      clearTimeout(timer);
      lastError = err;
    }
  }
  throw lastError;
}

/**
 * Query OSV database for known vulnerabilities in the given dependencies.
 * Uses batch API to minimize network calls.
 */
export async function queryOsv(
  deps: Dependency[]
): Promise<Map<string, Advisory[]>> {
  const result = new Map<string, Advisory[]>();
  if (!deps.length) return result;

  // Check cache first — separate cached from uncached deps
  const uncachedDeps: Dependency[] = [];
  for (const d of deps) {
    const key = `${d.ecosystem}:${d.name}@${d.version}`;
    const cached = getCached(key);
    if (cached !== null) {
      if (cached.length > 0) result.set(key, cached);
    } else {
      uncachedDeps.push(d);
    }
  }

  if (!uncachedDeps.length) return result;

  let successCount = 0;
  let totalBatches = 0;

  // Process uncached deps in batches
  for (let i = 0; i < uncachedDeps.length; i += BATCH_SIZE) {
    totalBatches++;
    const batch = uncachedDeps.slice(i, i + BATCH_SIZE);
    const queries: OsvQuery[] = batch.map((d) => ({
      package: { name: d.name, ecosystem: d.ecosystem },
      version: d.version,
    }));

    try {
      const res = await fetchWithTimeout(OSV_BATCH_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ queries }),
      });

      if (!res.ok) continue;
      successCount++;

      const data = (await res.json()) as OsvBatchResult;

      // Collect all vuln IDs that need detail fetching
      const vulnIdsToFetch: { depKey: string; vulnId: string }[] = [];

      for (let j = 0; j < data.results.length; j++) {
        const vulns = data.results[j].vulns;
        if (!vulns?.length) continue;

        const dep = batch[j];
        const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;

        for (const v of vulns) {
          vulnIdsToFetch.push({ depKey: key, vulnId: v.id });
        }
      }

      // Fetch vulnerability details in parallel (max 20 concurrent)
      const details = await fetchVulnDetails(
        vulnIdsToFetch.map((v) => v.vulnId)
      );

      // Group advisories per dep key for caching
      const batchAdvisories = new Map<string, Advisory[]>();
      for (const { depKey, vulnId } of vulnIdsToFetch) {
        const detail = details.get(vulnId);
        if (!detail) continue;

        const existing = result.get(depKey) ?? [];
        existing.push(detail);
        result.set(depKey, existing);

        const ba = batchAdvisories.get(depKey) ?? [];
        ba.push(detail);
        batchAdvisories.set(depKey, ba);
      }

      // Cache results (including deps with zero vulns)
      for (const dep of batch) {
        const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;
        setCache(key, batchAdvisories.get(key) ?? []);
      }
    } catch {
      // Network error — skip this batch
    }
  }

  // If ALL batches failed, throw so the caller knows SCA was skipped
  if (successCount === 0 && totalBatches > 0) {
    throw new Error("OSV API unreachable");
  }

  return result;
}

/** Fetch individual vulnerability details from OSV */
async function fetchVulnDetails(
  ids: string[]
): Promise<Map<string, Advisory>> {
  const result = new Map<string, Advisory>();
  const unique = [...new Set(ids)];

  // Fetch in parallel with concurrency limit
  const CONCURRENCY = 20;
  for (let i = 0; i < unique.length; i += CONCURRENCY) {
    const batch = unique.slice(i, i + CONCURRENCY);
    const promises = batch.map(async (id) => {
      try {
        const res = await fetchWithTimeout(`${OSV_VULN_URL}/${id}`, {
          method: "GET",
          headers: { Accept: "application/json" },
        });
        if (!res.ok) return;
        const vuln = (await res.json()) as OsvVuln;
        result.set(id, osvToAdvisory(vuln));
      } catch {
        // Skip on error
      }
    });
    await Promise.all(promises);
  }

  return result;
}

/** Convert OSV vulnerability response to our Advisory type */
function osvToAdvisory(vuln: OsvVuln): Advisory {
  // Extract CVSS score
  let cvssScore: number | null = null;
  const cvss = vuln.severity?.find((s) => s.type === "CVSS_V3");
  if (cvss?.score) {
    const parsed = parseFloat(cvss.score);
    if (!isNaN(parsed)) cvssScore = parsed;
  }

  // Determine severity from CVSS or database_specific
  const severity = cvssToSeverity(
    cvssScore,
    vuln.database_specific?.severity
  );

  // Extract fixed version
  let fixedVersion: string | null = null;
  for (const aff of vuln.affected ?? []) {
    for (const range of aff.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) {
          fixedVersion = event.fixed;
          break;
        }
      }
      if (fixedVersion) break;
    }
    if (fixedVersion) break;
  }

  // Extract affected versions
  const affected: string[] = [];
  for (const aff of vuln.affected ?? []) {
    if (aff.versions) affected.push(...aff.versions);
  }

  return {
    id: vuln.id,
    summary: vuln.summary ?? "No summary available",
    details: vuln.details ?? "",
    severity,
    aliases: vuln.aliases ?? [],
    cvssScore,
    affected,
    fixedVersion,
    references: (vuln.references ?? []).map((r) => r.url),
  };
}

/** Map CVSS score or severity string to our severity type */
function cvssToSeverity(
  score: number | null,
  dbSeverity?: string
): "critical" | "warning" | "info" {
  if (score !== null) {
    if (score >= 7.0) return "critical";
    if (score >= 4.0) return "warning";
    return "info";
  }

  if (dbSeverity) {
    const lower = dbSeverity.toLowerCase();
    if (lower === "critical" || lower === "high") return "critical";
    if (lower === "moderate" || lower === "medium") return "warning";
    return "info";
  }

  return "warning";
}
