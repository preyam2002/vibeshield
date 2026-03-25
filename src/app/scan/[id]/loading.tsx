export default function ScanLoading() {
  return (
    <div className="min-h-screen">
      <nav className="border-b border-zinc-800/50 px-6 py-4">
        <div className="max-w-5xl mx-auto flex items-center justify-between">
          <div className="h-6 w-24 bg-zinc-800/50 rounded animate-pulse" />
          <div className="h-6 w-16 bg-zinc-800/50 rounded animate-pulse" />
        </div>
      </nav>
      <main className="max-w-5xl mx-auto px-4 py-8">
        <div className="flex items-start gap-6 mb-8">
          <div className="w-20 h-20 bg-zinc-800/30 rounded-2xl animate-pulse" />
          <div className="flex-1 space-y-3">
            <div className="h-8 w-64 bg-zinc-800/30 rounded animate-pulse" />
            <div className="h-4 w-48 bg-zinc-800/20 rounded animate-pulse" />
            <div className="flex gap-2">
              {Array.from({ length: 5 }).map((_, i) => (
                <div key={i} className="h-16 w-20 bg-zinc-800/20 rounded-lg animate-pulse" />
              ))}
            </div>
          </div>
        </div>
        <div className="space-y-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="h-14 bg-zinc-800/20 rounded-lg animate-pulse" style={{ animationDelay: `${i * 100}ms` }} />
          ))}
        </div>
      </main>
    </div>
  );
}
