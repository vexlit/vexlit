"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";

type Schedule = "none" | "daily" | "weekly";

export function ProjectSchedule({
  projectId,
  currentSchedule,
}: {
  projectId: string;
  currentSchedule: Schedule;
}) {
  const router = useRouter();
  const [schedule, setSchedule] = useState<Schedule>(currentSchedule);
  const [saving, setSaving] = useState(false);

  const handleChange = async (value: Schedule) => {
    setSchedule(value);
    setSaving(true);
    try {
      const res = await fetch(`/api/projects/${projectId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scan_schedule: value }),
      });
      if (res.ok) {
        toast.success(value === "none" ? "Scheduled scan disabled" : `Scheduled scan: ${value}`);
        router.refresh();
      } else {
        toast.error("Failed to update schedule");
        setSchedule(currentSchedule);
      }
    } catch {
      toast.error("Failed to update schedule");
      setSchedule(currentSchedule);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-white text-sm font-medium">Scheduled Scan</h3>
          <p className="text-gray-500 text-xs mt-0.5">
            Automatically scan this project on a schedule
          </p>
        </div>
        <select
          value={schedule}
          onChange={(e) => handleChange(e.target.value as Schedule)}
          disabled={saving}
          className="px-3 py-1.5 bg-gray-800 border border-gray-700 rounded-lg text-white text-sm focus:outline-none focus:border-red-500 disabled:opacity-50"
        >
          <option value="none">Disabled</option>
          <option value="daily">Daily</option>
          <option value="weekly">Weekly</option>
        </select>
      </div>
    </div>
  );
}
