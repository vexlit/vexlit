/**
 * Public GitHub repo scanner utilities.
 * Set GITHUB_TOKEN env var for 5000 req/hr (vs 60 unauthenticated).
 */
const GITHUB_API = "https://api.github.com";

const SUPPORTED_EXTENSIONS = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".py"];
const SCA_FILES = new Set(["package.json", "requirements.txt", "Pipfile"]);
const MAX_FILE_SIZE = 1_000_000; // 1MB per file
const MAX_SCANNABLE_FILES = 200;

const SKIP_DIRECTORIES = [
  "node_modules", "dist", "build", "out", "target", "tmp",
  ".cache", ".next", "coverage", ".git", "vendor", "__pycache__", ".venv", "venv",
];

interface TreeItem {
  path: string;
  type: "blob" | "tree";
  size?: number;
}

/** GitHub API fetch with optional server-side token for higher rate limits */
async function ghPublicFetch<T>(path: string): Promise<T> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };

  // Use server-side GitHub token if available (5000 req/hr vs 60 req/hr)
  const serverToken = process.env.GITHUB_TOKEN;
  if (serverToken) {
    headers.Authorization = `Bearer ${serverToken}`;
  }

  const res = await fetch(`${GITHUB_API}${path}`, { headers });

  if (!res.ok) {
    if (res.status === 404) throw new Error("Repository not found or is private");
    if (res.status === 403) {
      const remaining = res.headers.get("x-ratelimit-remaining");
      if (remaining === "0") throw new Error("GitHub API rate limit exceeded. Try again later.");
    }
    throw new Error(`GitHub API error: ${res.status}`);
  }

  return res.json() as Promise<T>;
}

/** Get default branch for a public repo */
export async function fetchPublicDefaultBranch(owner: string, repo: string): Promise<string> {
  const data = await ghPublicFetch<{ default_branch: string }>(`/repos/${owner}/${repo}`);
  return data.default_branch;
}

/** Get scannable file paths from a public repo */
export async function fetchPublicRepoTree(owner: string, repo: string, branch: string): Promise<string[]> {
  const tree = await ghPublicFetch<{ tree: TreeItem[]; truncated: boolean }>(
    `/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`
  );

  return tree.tree
    .filter((item) => {
      if (item.type !== "blob") return false;
      if (item.size && item.size > MAX_FILE_SIZE) return false;
      const parts = item.path.split("/");
      if (parts.some((p) => SKIP_DIRECTORIES.includes(p))) return false;
      const fileName = item.path.split("/").pop() ?? "";
      if (SCA_FILES.has(fileName)) return true;
      const ext = "." + fileName.split(".").pop()?.toLowerCase();
      return SUPPORTED_EXTENSIONS.includes(ext);
    })
    .slice(0, MAX_SCANNABLE_FILES)
    .map((item) => item.path);
}

/** Fetch file contents for a batch of paths from a public repo */
export async function fetchPublicFilesBatch(
  owner: string,
  repo: string,
  branch: string,
  paths: string[]
): Promise<{ path: string; content: string }[]> {
  const PARALLEL = 15;
  const files: { path: string; content: string }[] = [];

  for (let i = 0; i < paths.length; i += PARALLEL) {
    const batch = paths.slice(i, i + PARALLEL);
    const results = await Promise.all(
      batch.map(async (filePath) => {
        try {
          const data = await ghPublicFetch<{ content: string; encoding: string }>(
            `/repos/${owner}/${repo}/contents/${filePath}?ref=${branch}`
          );
          if (data.encoding === "base64") {
            return { path: filePath, content: Buffer.from(data.content, "base64").toString("utf-8") };
          }
          return { path: filePath, content: data.content };
        } catch {
          return null;
        }
      })
    );
    for (const r of results) {
      if (r) files.push(r);
    }
  }

  return files;
}
