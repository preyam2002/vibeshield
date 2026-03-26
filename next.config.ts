import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  serverExternalPackages: ["cheerio", "better-sqlite3", "pino"],
  ...(process.env.STANDALONE === "1" && {
    output: "standalone" as const,
    outputFileTracingRoot: process.cwd(),
  }),
};

export default nextConfig;
