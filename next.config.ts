import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  serverExternalPackages: ["cheerio"],
  ...(process.env.STANDALONE === "1" && {
    output: "standalone" as const,
    outputFileTracingRoot: process.cwd(),
  }),
};

export default nextConfig;
