"use client";

import dynamic from "next/dynamic";

const SeverityDonut = dynamic(
  () => import("./severity-donut").then((m) => m.SeverityDonut),
  { ssr: false }
);

export function LazySeverityDonut(props: {
  critical: number;
  warning: number;
  info: number;
  size?: number;
}) {
  return <SeverityDonut {...props} />;
}
