"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";

type ScanMode = "github" | "upload";

interface Repo {
  id: number;
  name: string;
  full_name: string;
  private: boolean;
  default_branch: string;
  language: string | null;
  updated_at: string;
}

interface Branch {
  name: string;
  sha: string;
}

export default function NewScanPage() {
  const router = useRouter();
  const [mode, setMode] = useState<ScanMode>("github");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // GitHub mode state
  const [repos, setRepos] = useState<Repo[]>([]);
  const [reposLoading, setReposLoading] = useState(false);
  const [reposError, setReposError] = useState("");
  const [selectedRepo, setSelectedRepo] = useState<Repo | null>(null);
  const [branches, setBranches] = useState<Branch[]>([]);
  const [branchesLoading, setBranchesLoading] = useState(false);
  const [selectedBranch, setSelectedBranch] = useState("");
  const [repoSearch, setRepoSearch] = useState("");
  const [githubUrlInput, setGithubUrlInput] = useState("");

  // Upload mode state
  const [projectName, setProjectName] = useState("");
  const [files, setFiles] = useState<FileList | null>(null);

  // Fetch repos on mount
  useEffect(() => {
    async function loadRepos() {
      setReposLoading(true);
      setReposError("");
      try {
        const res = await fetch("/api/github/repos");
        if (!res.ok) {
          const data = await res.json();
          setReposError(data.error ?? "Failed to load repositories");
          return;
        }
        const data = await res.json();
        setRepos(data);
      } catch {
        setReposError("Failed to connect to GitHub");
      } finally {
        setReposLoading(false);
      }
    }
    loadRepos();
  }, []);

  // Fetch branches when repo is selected
  useEffect(() => {
    if (!selectedRepo) {
      setBranches([]);
      setSelectedBranch("");
      return;
    }

    async function loadBranches() {
      if (!selectedRepo) return;
      setBranchesLoading(true);
      const [owner, repo] = selectedRepo.full_name.split("/");
      try {
        const res = await fetch(
          `/api/github/repos/${owner}/${repo}/branches`
        );
        if (res.ok) {
          const data = await res.json();
          setBranches(data);
          setSelectedBranch(selectedRepo.default_branch);
        }
      } catch {
        // ignore
      } finally {
        setBranchesLoading(false);
      }
    }
    loadBranches();
  }, [selectedRepo]);

  /** Parse owner/repo from a GitHub URL like https://github.com/owner/repo */
  function parseGithubUrl(url: string): { owner: string; repo: string } | null {
    const match = url
      .trim()
      .match(/github\.com\/([^/\s]+)\/([^/\s#?]+)/);
    if (!match) return null;
    return { owner: match[1], repo: match[2].replace(/\.git$/, "") };
  }

  const handleGitHubScan = async () => {
    // Determine owner/repo from selected repo or URL input
    let owner: string;
    let repo: string;
    let branchToUse: string | undefined = selectedBranch || undefined;

    if (selectedRepo) {
      [owner, repo] = selectedRepo.full_name.split("/");
    } else if (githubUrlInput.trim()) {
      const parsed = parseGithubUrl(githubUrlInput);
      if (!parsed) {
        setError("Invalid GitHub URL. Use: https://github.com/owner/repo");
        return;
      }
      owner = parsed.owner;
      repo = parsed.repo;
      branchToUse = undefined; // use default branch
    } else {
      setError("Select a repository or enter a GitHub URL");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          owner,
          repo,
          branch: branchToUse,
        }),
      });
      const data = await res.json();

      if (!res.ok) {
        setError(data.error ?? "Scan failed");
        return;
      }

      router.push(`/dashboard/scans/${data.scanId}`);
    } catch {
      setError("Network error");
    } finally {
      setLoading(false);
    }
  };

  const handleUploadScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!projectName.trim()) {
      setError("Project name is required");
      return;
    }
    if (!files?.length) {
      setError("Upload at least one file");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const formData = new FormData();
      formData.append("projectName", projectName.trim());
      if (files) {
        for (let i = 0; i < files.length; i++) {
          formData.append("files", files[i]);
        }
      }

      const res = await fetch("/api/scan", { method: "POST", body: formData });
      const data = await res.json();

      if (!res.ok) {
        setError(data.error ?? "Scan failed");
        return;
      }

      router.push(`/dashboard/scans/${data.scanId}`);
    } catch {
      setError("Network error");
    } finally {
      setLoading(false);
    }
  };

  const filteredRepos = repoSearch
    ? repos.filter((r) =>
        r.full_name.toLowerCase().includes(repoSearch.toLowerCase())
      )
    : repos;

  return (
    <div className="max-w-2xl">
      <h1 className="text-2xl font-bold text-white mb-6">New Scan</h1>

      {/* Mode toggle */}
      <div className="flex gap-2 mb-6">
        <button
          onClick={() => { setMode("github"); setError(""); }}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            mode === "github"
              ? "bg-gray-800 text-white"
              : "text-gray-500 hover:text-gray-300"
          }`}
        >
          <span className="flex items-center gap-2">
            <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
              <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" />
            </svg>
            GitHub Repository
          </span>
        </button>
        <button
          onClick={() => { setMode("upload"); setError(""); }}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            mode === "upload"
              ? "bg-gray-800 text-white"
              : "text-gray-500 hover:text-gray-300"
          }`}
        >
          <span className="flex items-center gap-2">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
            </svg>
            Upload Files
          </span>
        </button>
      </div>

      {mode === "github" && (
        <div className="space-y-4">
          {/* GitHub URL input */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              GitHub Repository URL
              <span className="text-gray-500 font-normal"> (any public repo)</span>
            </label>
            <input
              type="text"
              value={githubUrlInput}
              onChange={(e) => {
                setGithubUrlInput(e.target.value);
                if (e.target.value.trim()) setSelectedRepo(null);
              }}
              placeholder="https://github.com/owner/repo"
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-red-500"
            />
          </div>

          {/* Divider */}
          <div className="flex items-center gap-4">
            <div className="flex-1 border-t border-gray-800" />
            <span className="text-gray-500 text-sm">or select your repository</span>
            <div className="flex-1 border-t border-gray-800" />
          </div>

          {/* Repo search */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Your Repositories
            </label>
            <input
              type="text"
              value={repoSearch}
              onChange={(e) => setRepoSearch(e.target.value)}
              placeholder="Search repositories..."
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-red-500"
            />
          </div>

          {/* Repo list */}
          {reposLoading && (
            <div className="flex items-center gap-2 text-gray-500 text-sm py-4">
              <div className="w-4 h-4 border-2 border-gray-600 border-t-transparent rounded-full animate-spin" />
              Loading repositories...
            </div>
          )}

          {reposError && (
            <p className="text-red-400 text-sm">{reposError}</p>
          )}

          {!reposLoading && !reposError && (
            <div className="max-h-64 overflow-y-auto border border-gray-800 rounded-lg divide-y divide-gray-800">
              {filteredRepos.length === 0 && (
                <p className="text-gray-500 text-sm p-4">
                  {repoSearch ? "No matching repositories" : "No repositories found"}
                </p>
              )}
              {filteredRepos.map((repo) => (
                <button
                  key={repo.id}
                  onClick={() => { setSelectedRepo(repo); setGithubUrlInput(""); }}
                  className={`w-full text-left px-4 py-3 hover:bg-gray-800/50 transition-colors ${
                    selectedRepo?.id === repo.id ? "bg-gray-800" : ""
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-white text-sm">{repo.full_name}</span>
                      {repo.private && (
                        <span className="text-xs px-1.5 py-0.5 bg-yellow-900/50 text-yellow-400 rounded">
                          private
                        </span>
                      )}
                    </div>
                    {repo.language && (
                      <span className="text-gray-600 text-xs">{repo.language}</span>
                    )}
                  </div>
                </button>
              ))}
            </div>
          )}

          {/* Branch selector */}
          {selectedRepo && (
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Branch
              </label>
              {branchesLoading ? (
                <div className="flex items-center gap-2 text-gray-500 text-sm">
                  <div className="w-3 h-3 border-2 border-gray-600 border-t-transparent rounded-full animate-spin" />
                  Loading branches...
                </div>
              ) : (
                <select
                  value={selectedBranch}
                  onChange={(e) => setSelectedBranch(e.target.value)}
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white focus:outline-none focus:border-red-500"
                >
                  {branches.map((b) => (
                    <option key={b.name} value={b.name}>
                      {b.name}
                      {b.name === selectedRepo.default_branch ? " (default)" : ""}
                    </option>
                  ))}
                </select>
              )}
            </div>
          )}

          {error && <p className="text-red-400 text-sm">{error}</p>}

          <button
            onClick={handleGitHubScan}
            disabled={loading || (!selectedRepo && !githubUrlInput.trim())}
            className="w-full px-4 py-3 bg-red-600 text-white rounded-lg font-medium hover:bg-red-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? "Fetching & Scanning..." : "Start Scan"}
          </button>
        </div>
      )}

      {mode === "upload" && (
        <form onSubmit={handleUploadScan} className="space-y-6">
          {/* Project Name */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Project Name
            </label>
            <input
              type="text"
              value={projectName}
              onChange={(e) => setProjectName(e.target.value)}
              placeholder="my-project"
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-red-500"
            />
          </div>

          {/* File Upload */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Upload Code Files
              <span className="text-gray-500 font-normal">
                {" "}
                (.js, .ts, .py, .zip)
              </span>
            </label>
            <input
              type="file"
              multiple
              accept=".js,.jsx,.ts,.tsx,.py,.mjs,.cjs,.zip"
              onChange={(e) => setFiles(e.target.files)}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 border-dashed rounded-lg text-gray-400 file:mr-4 file:py-1 file:px-3 file:rounded file:border-0 file:bg-gray-800 file:text-gray-300 file:text-sm"
            />
          </div>

          {error && <p className="text-red-400 text-sm">{error}</p>}

          <button
            type="submit"
            disabled={loading}
            className="w-full px-4 py-3 bg-red-600 text-white rounded-lg font-medium hover:bg-red-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? "Scanning..." : "Start Scan"}
          </button>
        </form>
      )}
    </div>
  );
}
