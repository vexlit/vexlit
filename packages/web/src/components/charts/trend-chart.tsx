"use client";

import { useRef, useState, useEffect } from "react";
import { useTranslations } from "next-intl";
import { useTheme } from "@/components/theme-provider";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
} from "recharts";

interface TrendPoint {
  date: string;
  critical: number;
  warning: number;
  info: number;
  total: number;
}

export function TrendChart({ data }: { data: TrendPoint[] }) {
  const t = useTranslations("dashboard");
  const { theme } = useTheme();
  const isLight = theme === "light";
  const containerRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(0);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;

    // Use ResizeObserver contentRect (more reliable than clientWidth in Opera)
    const ro = new ResizeObserver((entries) => {
      const w = Math.floor(entries[0]?.contentRect?.width ?? 0);
      if (w > 0) setWidth(w);
    });
    ro.observe(el);

    // Fallback: rAF for first paint where ResizeObserver hasn't fired yet
    const raf = requestAnimationFrame(() => {
      const w = el.getBoundingClientRect().width;
      if (w > 0) setWidth(Math.floor(w));
    });

    return () => { ro.disconnect(); cancelAnimationFrame(raf); };
  }, []);

  if (data.length < 2) return null;

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
      <h3 className="text-sm font-medium text-gray-400 mb-4">
        {t("trendChart")}
      </h3>
      <div className="h-48" ref={containerRef}>
        {width > 0 && (
          <AreaChart data={data} width={width} height={192}>
            <XAxis
              dataKey="date"
              tick={{ fill: "#6b7280", fontSize: 11 }}
              axisLine={false}
              tickLine={false}
            />
            <YAxis
              tick={{ fill: "#6b7280", fontSize: 11 }}
              axisLine={false}
              tickLine={false}
              width={30}
              allowDecimals={false}
            />
            <Tooltip
              contentStyle={{
                background: isLight ? "#ffffff" : "#111827",
                border: `1px solid ${isLight ? "#e5e7eb" : "#374151"}`,
                borderRadius: "8px",
                fontSize: "12px",
                color: isLight ? "#111827" : "#e5e7eb",
              }}
              labelStyle={{ color: isLight ? "#6b7280" : "#9ca3af" }}
              itemStyle={{ color: isLight ? "#374151" : "#e5e7eb" }}
            />
            <Area
              type="monotone"
              dataKey="critical"
              stroke="#ef4444"
              fill="rgba(239,68,68,0.15)"
              strokeWidth={2}
              stackId="1"
            />
            <Area
              type="monotone"
              dataKey="warning"
              stroke="#eab308"
              fill="rgba(234,179,8,0.15)"
              strokeWidth={2}
              stackId="1"
            />
            <Area
              type="monotone"
              dataKey="info"
              stroke="#3b82f6"
              fill="rgba(59,130,246,0.15)"
              strokeWidth={2}
              stackId="1"
            />
          </AreaChart>
        )}
      </div>
    </div>
  );
}
