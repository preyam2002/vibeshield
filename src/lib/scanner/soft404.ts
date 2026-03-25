import type { ScanTarget } from "./types";

/**
 * Extract the structural skeleton of an HTML document — just tag names in order.
 * Two pages with the same skeleton are almost certainly the same template.
 */
const extractSkeleton = (html: string): string => {
  const tags: string[] = [];
  const re = /<\/?([a-z][a-z0-9]*)/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null && tags.length < 200) {
    tags.push(m[1].toLowerCase());
  }
  return tags.join(",");
};

/**
 * Checks if a response body is likely a soft 404 — i.e. the same page the SPA
 * returns for any unknown route. This prevents false positives on SPAs that
 * return 200 + their shell HTML for every path.
 *
 * Uses three signals: exact match, structural skeleton comparison, and
 * normalized content similarity (non-prefix to handle dynamic content mid-page).
 */
export const isSoft404 = (body: string, target: ScanTarget): boolean => {
  if (!target.soft404Body) return false;

  const canary = target.soft404Body;

  // Exact match
  if (body === canary) return true;

  // Length must be in the same ballpark
  const lenRatio = canary.length > 0 ? body.length / canary.length : 0;
  if (lenRatio < 0.5 || lenRatio > 2.0) return false;

  // Structural skeleton comparison — if tag structure matches, it's the same template
  const bodySkeleton = extractSkeleton(body);
  const canarySkeleton = extractSkeleton(canary);
  if (bodySkeleton.length > 20 && bodySkeleton === canarySkeleton) return true;

  // Normalized content similarity (strip scripts/styles/whitespace, compare character overlap)
  const normalize = (s: string) =>
    s.replace(/<script[\s\S]*?<\/script>/gi, "")
      .replace(/<style[\s\S]*?<\/style>/gi, "")
      .replace(/<[^>]+>/g, " ")
      .replace(/\s+/g, " ")
      .trim()
      .substring(0, 1500);

  const a = normalize(body);
  const b = normalize(canary);
  if (a.length < 20 || b.length < 20) return false;

  // Character-level similarity using sampling (not just prefix)
  const minLen = Math.min(a.length, b.length);
  let matches = 0;
  const step = Math.max(1, Math.floor(minLen / 200));
  let samples = 0;
  for (let i = 0; i < minLen; i += step) {
    if (a[i] === b[i]) matches++;
    samples++;
  }

  return matches / samples > 0.85;
};

/**
 * For non-HTML responses (JSON APIs that might be SPA catch-alls returning HTML),
 * check if the response looks like HTML when we expected JSON/API data.
 */
export const looksLikeHtml = (body: string): boolean => {
  const trimmed = body.trimStart();
  return trimmed.startsWith("<!") || trimmed.startsWith("<html") || trimmed.startsWith("<head");
};
