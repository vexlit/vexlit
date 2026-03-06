"use client";

import dynamic from "next/dynamic";

const TrendChart = dynamic(
  () => import("./trend-chart").then((m) => m.TrendChart),
  { ssr: false }
);

export function LazyTrendChart(props: {
  data: { date: string; critical: number; warning: number; info: number; total: number }[];
}) {
  return <TrendChart {...props} />;
}
