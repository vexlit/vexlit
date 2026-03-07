"use client";

import dynamic from "next/dynamic";

const TrendChart = dynamic(
  () => import("./trend-chart").then((m) => m.TrendChart),
  {
    ssr: false,
    loading: () => (
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
        <div className="h-4 w-32 bg-gray-800 rounded mb-4" />
        <div className="h-48 bg-gray-800/30 rounded animate-pulse" />
      </div>
    ),
  }
);

export function LazyTrendChart(props: {
  data: { date: string; critical: number; warning: number; info: number; total: number }[];
}) {
  return <TrendChart {...props} />;
}
