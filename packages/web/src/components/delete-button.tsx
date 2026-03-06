"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";

interface DeleteButtonProps {
  endpoint: string;
  redirectTo: string;
  label: string;
  confirmMessage: string;
}

export function DeleteButton({ endpoint, redirectTo, label, confirmMessage }: DeleteButtonProps) {
  const router = useRouter();
  const [confirming, setConfirming] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const handleDelete = async () => {
    setDeleting(true);
    try {
      const res = await fetch(endpoint, { method: "DELETE" });
      if (res.ok) {
        toast.success("Deleted successfully");
        router.push(redirectTo);
        router.refresh();
      } else {
        const data = await res.json();
        toast.error(data.error ?? "Failed to delete");
      }
    } finally {
      setDeleting(false);
      setConfirming(false);
    }
  };

  if (!confirming) {
    return (
      <button
        onClick={() => setConfirming(true)}
        className="text-gray-500 hover:text-red-400 text-sm transition-colors"
      >
        {label}
      </button>
    );
  }

  return (
    <div className="flex items-center gap-2">
      <span className="text-red-400 text-sm">{confirmMessage}</span>
      <button
        onClick={handleDelete}
        disabled={deleting}
        className="px-3 py-1 bg-red-600 text-white text-xs rounded-lg hover:bg-red-700 transition-colors disabled:opacity-50"
      >
        {deleting ? "Deleting..." : "Confirm"}
      </button>
      <button
        onClick={() => setConfirming(false)}
        className="px-3 py-1 bg-gray-800 text-gray-400 text-xs rounded-lg hover:bg-gray-700 transition-colors"
      >
        Cancel
      </button>
    </div>
  );
}
