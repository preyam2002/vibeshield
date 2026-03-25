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

interface CrlfTest {
  endpoint: string;
  pathname: string;
  param: string;
  payload: string;
}

export const crlfModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const tested = new Set<string>();

  const endpoints = [target.url, ...target.pages.slice(0, 5), ...target.apiEndpoints.slice(0, 5)];

  // Build all test cases upfront
  const tests: CrlfTest[] = [];
  for (const endpoint of endpoints) {
    try {
      const url = new URL(endpoint);
      const pathname = url.pathname;
      if (tested.has(pathname)) continue;
      tested.add(pathname);

      const params = [...url.searchParams.keys()];
      const testParams = params.length > 0 ? params.slice(0, 3) : CRLF_PARAMS.slice(0, 3);

      for (const param of testParams) {
        for (const payload of CRLF_PAYLOADS.slice(0, 3)) {
          tests.push({ endpoint, pathname, param, payload });
        }
      }
    } catch { /* skip */ }
  }

  const results = await Promise.allSettled(
    tests.map(async ({ endpoint, pathname, param, payload }) => {
      const testUrl = new URL(endpoint);
      testUrl.searchParams.set(param, payload);
      const res = await scanFetch(testUrl.href, { timeoutMs: 5000 });

      const injectedHeader = res.headers.get("x-injected");
      const injectedCookie = (res.headers.get("set-cookie") || "").includes("crlf=injected");

      if (injectedHeader || injectedCookie) {
        return {
          type: "header" as const,
          pathname, param, payload, injectedHeader,
        };
      }

      const text = await res.text();
      if (text.includes("\nX-Injected: true") && payload.includes("X-Injected")) {
        return { type: "split" as const, pathname, param, payload };
      }

      return null;
    }),
  );

  const seenPaths = new Set<string>();
  for (const r of results) {
    if (findings.length >= 3) break;
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    const key = `${v.pathname}:${v.param}`;
    if (seenPaths.has(key)) continue;
    seenPaths.add(key);

    if (v.type === "header") {
      findings.push({
        id: `crlf-${findings.length}`,
        module: "CRLF Injection",
        severity: "high",
        title: `CRLF injection on ${v.pathname} (param: ${v.param})`,
        description: "HTTP response headers can be injected via CRLF characters in user input. Attackers can set arbitrary cookies, redirect users, or perform response splitting attacks.",
        evidence: `Payload: ${v.param}=${v.payload}\n${v.injectedHeader ? `Injected header: X-Injected: ${v.injectedHeader}` : `Injected cookie: crlf=injected`}`,
        remediation: "Strip or encode \\r\\n characters from all user input before using it in HTTP headers or redirects. Use framework-provided redirect functions that handle encoding.",
        cwe: "CWE-93",
        owasp: "A03:2021",
      });
    } else {
      findings.push({
        id: `crlf-split-${findings.length}`,
        module: "CRLF Injection",
        severity: "medium",
        title: `HTTP response splitting on ${v.pathname} (param: ${v.param})`,
        description: "CRLF characters in input cause content injection in the HTTP response body. This indicates the server doesn't strip newline characters from user input.",
        evidence: `Payload: ${v.param}=${v.payload}\nInjected content appears on its own line in response body`,
        remediation: "Strip or encode \\r\\n characters from all user input. Use framework-provided response methods.",
        cwe: "CWE-113",
        owasp: "A03:2021",
      });
    }
  }

  return findings;
};
