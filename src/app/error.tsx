"use client";

export default function GlobalError({ error, reset }: { error: Error; reset: () => void }) {
  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="text-center space-y-4 max-w-md px-4">
        <div className="text-4xl font-black text-red-400">Something broke</div>
        <p className="text-sm text-zinc-500">{error.message || "An unexpected error occurred."}</p>
        <div className="flex items-center justify-center gap-3">
          <button
            onClick={reset}
            className="text-sm bg-linear-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 text-white px-5 py-2 rounded-lg transition-colors"
          >
            Try again
          </button>
          <a href="/" className="text-sm text-zinc-500 hover:text-zinc-300 transition-colors">
            Go home
          </a>
        </div>
      </div>
    </div>
  );
}
