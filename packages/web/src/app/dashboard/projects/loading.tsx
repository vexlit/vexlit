export default function ProjectsLoading() {
  return (
    <div className="space-y-6 animate-pulse">
      <div className="flex items-center justify-between">
        <div>
          <div className="h-7 w-28 bg-gray-800 rounded" />
          <div className="h-4 w-40 bg-gray-800/60 rounded mt-2" />
        </div>
        <div className="h-9 w-24 bg-gray-800 rounded-lg" />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="bg-gray-900 border border-gray-800 rounded-xl p-4">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-gray-700" />
                  <div className="h-5 w-32 bg-gray-800 rounded" />
                </div>
                <div className="h-3 w-24 bg-gray-800/60 rounded mt-1.5 ml-4" />
              </div>
              <div className="w-12 h-12 rounded-full bg-gray-800" />
            </div>
            <div className="mt-3 pt-3 border-t border-gray-800">
              <div className="h-4 w-24 bg-gray-800/60 rounded" />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
