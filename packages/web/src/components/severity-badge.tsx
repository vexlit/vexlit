const SEVERITY_STYLES = {
  critical: "bg-red-500/10 text-red-400 border-red-500/20",
  warning: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
  info: "bg-blue-500/10 text-blue-400 border-blue-500/20",
} as const;

export function SeverityBadge({
  severity,
  count,
}: {
  severity: "critical" | "warning" | "info";
  count?: number;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium border ${SEVERITY_STYLES[severity]}`}
    >
      {count !== undefined ? `${count} ` : ""}
      {severity}
    </span>
  );
}
