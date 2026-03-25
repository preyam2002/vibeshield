import type { MetadataRoute } from "next";

export default function sitemap(): MetadataRoute.Sitemap {
  const base = process.env.NEXT_PUBLIC_URL || "https://vibeshield.dev";
  return [
    { url: base, lastModified: new Date(), changeFrequency: "daily", priority: 1 },
    { url: `${base}/docs`, lastModified: new Date(), changeFrequency: "weekly", priority: 0.8 },
    { url: `${base}/scans`, lastModified: new Date(), changeFrequency: "hourly", priority: 0.6 },
  ];
}
