"use client";

export default function ScanError({ error, reset }: { error: Error; reset: () => void }) {
  return (
    <div className="min-h-screen flex flex-col items-center justify-center gap-4">
      <a href="/" className="text-lg font-bold text-transparent bg-clip-text bg-linear-to-r from-red-500 to-orange-400">
        VibeShield
      </a>
      <div className="bg-zinc-900/50 border border-zinc-800/50 rounded-xl p-8 text-center max-w-sm">
        <div className="text-2xl mb-2">Something went wrong</div>
        <p className="text-sm text-zinc-500 mb-4">
          {error.message || "Failed to load scan results. The data may be corrupted or unavailable."}
        </p>
        <div className="flex gap-3 justify-center">
          <button
            onClick={reset}
            className="text-xs bg-zinc-900 border border-zinc-800 hover:border-zinc-700 text-zinc-400 px-4 py-2 rounded-lg transition-colors"
          >
            Try again
          </button>
          <a
            href="/"
            className="text-xs bg-linear-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 text-white px-4 py-2 rounded-lg transition-colors"
          >
            New Scan
          </a>
        </div>
      </div>
    </div>
  );
}
