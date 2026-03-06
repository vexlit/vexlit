export function Skeleton({ className = "" }: { className?: string }) {
  return (
    <div
      className={`animate-pulse bg-gray-800 light:bg-gray-200 rounded ${className}`}
    />
  );
}

export function CardSkeleton() {
  return (
    <div className="bg-gray-900 light:bg-white border border-gray-800 light:border-gray-200 rounded-lg p-4 space-y-3">
      <Skeleton className="h-5 w-3/4" />
      <Skeleton className="h-4 w-1/2" />
      <Skeleton className="h-3 w-1/4" />
    </div>
  );
}

export function TableRowSkeleton() {
  return (
    <tr className="border-b border-gray-800 light:border-gray-200">
      <td className="px-4 py-3"><Skeleton className="h-4 w-24" /></td>
      <td className="px-4 py-3"><Skeleton className="h-4 w-16" /></td>
      <td className="px-4 py-3"><Skeleton className="h-4 w-32" /></td>
      <td className="px-4 py-3"><Skeleton className="h-4 w-20" /></td>
    </tr>
  );
}

export function ScanDetailSkeleton() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-8 w-24 rounded-full" />
      </div>
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="bg-gray-900 light:bg-white border border-gray-800 light:border-gray-200 rounded-lg p-4">
            <Skeleton className="h-3 w-16 mb-2" />
            <Skeleton className="h-8 w-12" />
          </div>
        ))}
      </div>
      {Array.from({ length: 3 }).map((_, i) => (
        <div key={i} className="bg-gray-900 light:bg-white border border-gray-800 light:border-gray-200 rounded-lg p-4 space-y-3">
          <Skeleton className="h-4 w-64" />
          <Skeleton className="h-16 w-full" />
          <Skeleton className="h-4 w-48" />
        </div>
      ))}
    </div>
  );
}
