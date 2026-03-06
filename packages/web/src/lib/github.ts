const GITHUB_API = "https://api.github.com";

interface GitHubRepo {
  id: number;
  name: string;
  full_name: string;
  private: boolean;
  default_branch: string;
  language: string | null;
  updated_at: string;
}

interface GitHubBranch {
  name: string;
  commit: { sha: string };
}

interface GitHubTreeItem {
  path: string;
  type: "blob" | "tree";
  sha: string;
  size?: number;
}

interface GitHubFileContent {
  path: string;
  content: string;
}

const SUPPORTED_EXTENSIONS = [
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".ts",
  ".tsx",
  ".py",
];

/** Dependency manifest and lockfiles to include for SCA */
const SCA_FILES = new Set([
  "package.json",
  "package-lock.json",
  "requirements.txt",
  "Pipfile",
  "go.mod",
  "go.sum",
  "Cargo.toml",
  "Cargo.lock",
]);

const MAX_FILE_SIZE = 100_000; // 100KB per file
const MAX_SCANNABLE_FILES = 200;

const SKIP_DIRECTORIES = [
  "node_modules",
  "dist",
  "build",
  "out",
  "target",
  "tmp",
  ".cache",
  ".next",
  "coverage",
  ".git",
  "vendor",
  "__pycache__",
  ".venv",
  "venv",
];

async function ghFetch<T>(path: string, token: string): Promise<T> {
  const res = await fetch(`${GITHUB_API}${path}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });

  if (!res.ok) {
    if (res.status === 401) {
      throw new Error(
        "GitHub token expired or revoked. Please reconnect your GitHub account."
      );
    }
    if (res.status === 403) {
      const remaining = res.headers.get("x-ratelimit-remaining");
      if (remaining === "0") {
        const resetAt = res.headers.get("x-ratelimit-reset");
        const resetDate = resetAt
          ? new Date(Number(resetAt) * 1000).toLocaleTimeString()
          : "soon";
        throw new Error(
          `GitHub API rate limit exceeded. Resets at ${resetDate}.`
        );
      }
    }
    const body = await res.text();
    throw new Error(`GitHub API ${res.status}: ${body}`);
  }

  return res.json() as Promise<T>;
}

export async function fetchUserRepos(token: string): Promise<GitHubRepo[]> {
  const repos = await ghFetch<GitHubRepo[]>(
    "/user/repos?sort=updated&per_page=100&type=all",
    token
  );
  return repos;
}

export async function fetchBranches(
  owner: string,
  repo: string,
  token: string
): Promise<GitHubBranch[]> {
  return ghFetch<GitHubBranch[]>(
    `/repos/${owner}/${repo}/branches?per_page=100`,
    token
  );
}

/** Fetch the file tree and return scannable file paths only */
export async function fetchRepoTree(
  owner: string,
  repo: string,
  branch: string,
  token: string
): Promise<string[]> {
  const tree = await ghFetch<{ tree: GitHubTreeItem[]; truncated: boolean }>(
    `/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`,
    token
  );

  return tree.tree
    .filter((item) => {
      if (item.type !== "blob") return false;
      const parts = item.path.split("/");
      if (parts.some((p) => SKIP_DIRECTORIES.includes(p))) return false;
      const fileName = item.path.split("/").pop() ?? "";
      // Always include dependency files regardless of size (lockfiles can be large)
      if (SCA_FILES.has(fileName)) return true;
      if (item.size && item.size > MAX_FILE_SIZE) return false;
      const ext = "." + fileName.split(".").pop()?.toLowerCase();
      return SUPPORTED_EXTENSIONS.includes(ext);
    })
    .slice(0, MAX_SCANNABLE_FILES)
    .map((item) => item.path);
}

/** Fetch file contents for a batch of paths (parallel, 20 at a time) */
export async function fetchFileContentsBatch(
  owner: string,
  repo: string,
  branch: string,
  paths: string[],
  token: string
): Promise<GitHubFileContent[]> {
  const PARALLEL = 20;
  const files: GitHubFileContent[] = [];

  for (let i = 0; i < paths.length; i += PARALLEL) {
    const batch = paths.slice(i, i + PARALLEL);
    const results = await Promise.all(
      batch.map(async (filePath) => {
        try {
          const data = await ghFetch<{ content: string; encoding: string }>(
            `/repos/${owner}/${repo}/contents/${filePath}?ref=${branch}`,
            token
          );
          if (data.encoding === "base64") {
            return {
              path: filePath,
              content: Buffer.from(data.content, "base64").toString("utf-8"),
            };
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

export async function fetchDefaultBranch(
  owner: string,
  repo: string,
  token: string
): Promise<{ branch: string; sha: string }> {
  const repoData = await ghFetch<{ default_branch: string }>(
    `/repos/${owner}/${repo}`,
    token
  );
  const branches = await fetchBranches(owner, repo, token);
  const defaultBranch = branches.find(
    (b) => b.name === repoData.default_branch
  );
  return {
    branch: repoData.default_branch,
    sha: defaultBranch?.commit.sha ?? "",
  };
}
