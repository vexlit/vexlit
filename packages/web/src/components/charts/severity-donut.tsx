"use client";

import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";

const COLORS = {
  critical: "#ef4444",
  warning: "#eab308",
  info: "#3b82f6",
  clean: "#22c55e",
};

export function SeverityDonut({
  critical,
  warning,
  info,
  size = 64,
}: {
  critical: number;
  warning: number;
  info: number;
  size?: number;
}) {
  const total = critical + warning + info;

  if (total === 0) {
    return (
      <div
        className="rounded-full border-4 border-green-500/30 flex items-center justify-center"
        style={{ width: size, height: size }}
      >
        <svg className="w-5 h-5 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
        </svg>
      </div>
    );
  }

  const data = [
    { name: "critical", value: critical },
    { name: "warning", value: warning },
    { name: "info", value: info },
  ].filter((d) => d.value > 0);

  return (
    <div style={{ width: size, height: size }} className="relative">
      <ResponsiveContainer>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={size * 0.3}
            outerRadius={size * 0.45}
            dataKey="value"
            stroke="none"
          >
            {data.map((entry) => (
              <Cell
                key={entry.name}
                fill={COLORS[entry.name as keyof typeof COLORS]}
              />
            ))}
          </Pie>
        </PieChart>
      </ResponsiveContainer>
      <div className="absolute inset-0 flex items-center justify-center">
        <span className="text-white text-xs font-bold">{total}</span>
      </div>
    </div>
  );
}
