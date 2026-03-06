const TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

interface CacheEntry {
  data: string;
  ts: number;
}

export function getAiCache(key: string): string | null {
  if (typeof window === "undefined") return null;
  const raw = localStorage.getItem(key);
  if (!raw) return null;

  try {
    const entry: CacheEntry = JSON.parse(raw);
    if (Date.now() - entry.ts > TTL_MS) {
      localStorage.removeItem(key);
      return null;
    }
    return entry.data;
  } catch {
    // Legacy plain-string entry — remove and treat as miss
    localStorage.removeItem(key);
    return null;
  }
}

export function setAiCache(key: string, data: string): void {
  const entry: CacheEntry = { data, ts: Date.now() };
  localStorage.setItem(key, JSON.stringify(entry));
}
