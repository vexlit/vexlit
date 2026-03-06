export default function ScansLoading() {
  return (
    <div className="space-y-6 animate-pulse">
      <div className="flex items-center justify-between">
        <div>
          <div className="h-7 w-20 bg-gray-800 rounded" />
          <div className="h-4 w-52 bg-gray-800/60 rounded mt-2" />
        </div>
        <div className="h-9 w-24 bg-gray-800 rounded-lg" />
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
        {/* Table header */}
        <div className="border-b border-gray-800 px-4 py-3 flex gap-8">
          {["w-20", "w-16", "w-28", "w-16", "w-20"].map((w, i) => (
            <div key={i} className={`h-3 ${w} bg-gray-800/60 rounded`} />
          ))}
        </div>
        {/* Table rows */}
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="border-b border-gray-800 last:border-0 px-4 py-3 flex gap-8 items-center">
            <div className="h-4 w-28 bg-gray-800 rounded" />
            <div className="h-5 w-16 bg-gray-800/60 rounded" />
            <div className="h-4 w-20 bg-gray-800/60 rounded" />
            <div className="h-4 w-12 bg-gray-800/60 rounded" />
            <div className="h-4 w-20 bg-gray-800/60 rounded" />
          </div>
        ))}
      </div>
    </div>
  );
}
