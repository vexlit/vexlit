"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

export default function NewScanPage() {
  const router = useRouter();
  const [projectName, setProjectName] = useState("");
  const [githubUrl, setGithubUrl] = useState("");
  const [files, setFiles] = useState<FileList | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!projectName.trim()) {
      setError("Project name is required");
      return;
    }
    if (!files?.length && !githubUrl.trim()) {
      setError("Upload files or provide a GitHub URL");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const formData = new FormData();
      formData.append("projectName", projectName.trim());
      if (githubUrl.trim()) formData.append("githubUrl", githubUrl.trim());
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

  return (
    <div className="max-w-2xl">
      <h1 className="text-2xl font-bold text-white mb-6">New Scan</h1>

      <form onSubmit={handleSubmit} className="space-y-6">
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

        {/* GitHub URL */}
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">
            GitHub Repository URL
            <span className="text-gray-500 font-normal"> (optional)</span>
          </label>
          <input
            type="url"
            value={githubUrl}
            onChange={(e) => setGithubUrl(e.target.value)}
            placeholder="https://github.com/owner/repo"
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-red-500"
          />
        </div>

        {/* Divider */}
        <div className="flex items-center gap-4">
          <div className="flex-1 border-t border-gray-800" />
          <span className="text-gray-500 text-sm">or upload files</span>
          <div className="flex-1 border-t border-gray-800" />
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

        {error && (
          <p className="text-red-400 text-sm">{error}</p>
        )}

        <button
          type="submit"
          disabled={loading}
          className="w-full px-4 py-3 bg-red-600 text-white rounded-lg font-medium hover:bg-red-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? "Scanning..." : "Start Scan"}
        </button>
      </form>
    </div>
  );
}
