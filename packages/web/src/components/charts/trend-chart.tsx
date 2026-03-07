"use client";

import { useRef, useState, useEffect } from "react";
import { useTranslations } from "next-intl";
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
  const containerRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(0);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const measure = () => setWidth(el.clientWidth);
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
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
                background: "#111827",
                border: "1px solid #374151",
                borderRadius: "8px",
                fontSize: "12px",
              }}
              labelStyle={{ color: "#9ca3af" }}
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
