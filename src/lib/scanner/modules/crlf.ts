import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

const CRLF_PAYLOADS = [
  "%0d%0aX-Injected: true",
  "%0d%0aSet-Cookie: crlf=injected",
  "\r\nX-Injected: true",
  "%0d%0a%0d%0a<script>alert(1)</script>",
  "%E5%98%8D%E5%98%8AX-Injected: true", // Unicode CRLF variant
];

const CRLF_PARAMS = ["url", "redirect", "return", "next", "dest", "path", "page", "view", "callback", "q", "search"];

export const crlfModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const tested = new Set<string>();

  const endpoints = [target.url, ...target.pages.slice(0, 5), ...target.apiEndpoints.slice(0, 5)];

  for (const endpoint of endpoints) {
    const pathname = new URL(endpoint).pathname;
    if (tested.has(pathname)) continue;
    tested.add(pathname);

    // Test existing query params first
    try {
      const url = new URL(endpoint);
      const params = [...url.searchParams.keys()];
      const testParams = params.length > 0 ? params.slice(0, 3) : CRLF_PARAMS.slice(0, 3);

      for (const param of testParams) {
        if (findings.length >= 3) break;

        for (const payload of CRLF_PAYLOADS.slice(0, 3)) {
          try {
            const testUrl = new URL(endpoint);
            testUrl.searchParams.set(param, payload);
            const res = await scanFetch(testUrl.href, { timeoutMs: 5000 });

            // Check if injected header appears in response headers
            const injectedHeader = res.headers.get("x-injected");
            const injectedCookie = (res.headers.get("set-cookie") || "").includes("crlf=injected");

            if (injectedHeader || injectedCookie) {
              findings.push({
                id: `crlf-${findings.length}`,
                module: "CRLF Injection",
                severity: "high",
                title: `CRLF injection on ${pathname} (param: ${param})`,
                description: "HTTP response headers can be injected via CRLF characters in user input. Attackers can set arbitrary cookies, redirect users, or perform response splitting attacks.",
                evidence: `Payload: ${param}=${payload}\n${injectedHeader ? `Injected header: X-Injected: ${injectedHeader}` : `Injected cookie: crlf=injected`}`,
                remediation: "Strip or encode \\r\\n characters from all user input before using it in HTTP headers or redirects. Use framework-provided redirect functions that handle encoding.",
                cwe: "CWE-93",
                owasp: "A03:2021",
              });
              break;
            }

            // Check for response body injection (response splitting)
            // Only flag if the injected content appears on its own line, not reflected inside URLs/attributes
            const text = await res.text();
            if (text.includes("\nX-Injected: true") && payload.includes("X-Injected")) {
              findings.push({
                id: `crlf-split-${findings.length}`,
                module: "CRLF Injection",
                severity: "medium",
                title: `HTTP response splitting on ${pathname} (param: ${param})`,
                description: "CRLF characters in input cause content injection in the HTTP response body. This indicates the server doesn't strip newline characters from user input.",
                evidence: `Payload: ${param}=${payload}\nInjected content appears on its own line in response body`,
                remediation: "Strip or encode \\r\\n characters from all user input. Use framework-provided response methods.",
                cwe: "CWE-113",
                owasp: "A03:2021",
              });
              break;
            }
          } catch {
            // skip
          }
        }
      }
    } catch {
      // skip
    }
  }

  return findings;
};
