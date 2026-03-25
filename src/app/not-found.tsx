import Link from "next/link";

export default function NotFound() {
  return (
    <div className="min-h-screen flex items-center justify-center">
      <div className="text-center space-y-4">
        <div className="text-6xl font-black text-transparent bg-clip-text bg-linear-to-r from-red-500 to-orange-400">
          404
        </div>
        <p className="text-zinc-400">This page doesn&#39;t exist.</p>
        <div className="flex items-center justify-center gap-3">
          <Link
            href="/"
            className="text-sm bg-linear-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 text-white px-5 py-2 rounded-lg transition-colors"
          >
            Scan something
          </Link>
          <Link href="/scans" className="text-sm text-zinc-500 hover:text-zinc-300 transition-colors">
            View scans
          </Link>
        </div>
      </div>
    </div>
  );
}
