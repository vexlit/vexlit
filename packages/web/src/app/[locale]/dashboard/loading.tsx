export default function DashboardLoading() {
  return (
    <div className="space-y-8 animate-pulse">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="h-7 w-32 bg-gray-800 rounded" />
          <div className="h-4 w-56 bg-gray-800/60 rounded mt-2" />
        </div>
        <div className="h-9 w-24 bg-gray-800 rounded-lg" />
      </div>

      {/* Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className={`bg-gray-900 border border-gray-800 rounded-xl p-4 ${i === 4 ? "col-span-2 lg:col-span-1" : ""}`}>
            <div className="h-3 w-16 bg-gray-800/60 rounded" />
            <div className="h-8 w-12 bg-gray-800 rounded mt-2" />
          </div>
        ))}
      </div>

      {/* Chart placeholder */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl h-64" />

      {/* Recent vulnerabilities */}
      <div>
        <div className="h-5 w-40 bg-gray-800 rounded mb-4" />
        <div className="bg-gray-900 border border-gray-800 rounded-xl divide-y divide-gray-800">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="flex items-start gap-3 px-4 py-3">
              <div className="w-2 h-2 rounded-full bg-gray-800 mt-1.5" />
              <div className="flex-1">
                <div className="h-4 w-48 bg-gray-800 rounded" />
                <div className="h-3 w-32 bg-gray-800/60 rounded mt-1.5" />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
