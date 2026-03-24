import type { ScanTarget } from "./types";

/**
 * Checks if a response body is likely a soft 404 — i.e. the same page the SPA
 * returns for any unknown route. This prevents false positives on SPAs that
 * return 200 + their shell HTML for every path.
 *
 * Comparison: body length within 30% of the canary AND HTML structure matches.
 */
export const isSoft404 = (body: string, target: ScanTarget): boolean => {
  if (!target.soft404Body) return false;

  const canary = target.soft404Body;

  // Exact match
  if (body === canary) return true;

  // Length-based heuristic: if body length is within 30% of canary, likely same page
  const lenRatio = body.length / canary.length;
  if (lenRatio < 0.7 || lenRatio > 1.3) return false;

  // Compare a normalized snippet (strip whitespace-heavy sections)
  const normalize = (s: string) =>
    s.replace(/<script[\s\S]*?<\/script>/gi, "")
      .replace(/\s+/g, " ")
      .substring(0, 1000);

  const a = normalize(body);
  const b = normalize(canary);

  // Simple similarity: shared prefix ratio
  let shared = 0;
  const minLen = Math.min(a.length, b.length);
  for (let i = 0; i < minLen; i++) {
    if (a[i] === b[i]) shared++;
    else break;
  }

  return shared / minLen > 0.8;
};

/**
 * For non-HTML responses (JSON APIs that might be SPA catch-alls returning HTML),
 * check if the response looks like HTML when we expected JSON/API data.
 */
export const looksLikeHtml = (body: string): boolean => {
  const trimmed = body.trimStart();
  return trimmed.startsWith("<!") || trimmed.startsWith("<html") || trimmed.startsWith("<head");
};
