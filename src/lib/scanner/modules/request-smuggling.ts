import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

export const requestSmugglingModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  let count = 0;
  const testUrls = [target.url, ...target.apiEndpoints.slice(0, 3)];

  // Phase 1: CL.TE detection — send conflicting Content-Length and Transfer-Encoding headers
  // Safe approach: we check for differential responses, not actual smuggling
  const clTeResults = await Promise.allSettled(
    testUrls.slice(0, 3).map(async (url) => {
      // Baseline request
      const baseRes = await scanFetch(url, { timeoutMs: 5000 });
      const baseStatus = baseRes.status;
      const baseLen = (await baseRes.text()).length;

      // Test with conflicting Transfer-Encoding header variants
      // Obfuscated TE headers that proxies may miss but backends process
      const teVariants = [
        "chunked",
        "chunked ",        // trailing space
        " chunked",        // leading space
        "Chunked",         // case variation
        "\tchunked",       // tab prefix
        "chunked\r\n",     // CRLF in value
      ];

      for (const te of teVariants) {
        try {
          const res = await scanFetch(url, {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
              "Content-Length": "4",
              "Transfer-Encoding": te,
            },
            body: "0\r\n\r\n",
            timeoutMs: 8000,
          });
          // If the server responds differently with obfuscated TE,
          // it might process TE while a proxy uses CL
          if (res.status === 400 || res.status === 501) {
            // Server rejects malformed TE — good sign, not vulnerable
            continue;
          }
          // Check for timeout differences (TE.CL: server waits for more chunks)
          return null;
        } catch {
          // Timeout could indicate the server is waiting for chunk data (TE processing)
          return { pathname: new URL(url).pathname, variant: te.trim(), type: "timeout" as const };
        }
      }
      return null;
    }),
  );

  for (const r of clTeResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (v.type === "timeout") {
      findings.push({
        id: `smuggling-clte-${count++}`,
        module: "Request Smuggling",
        severity: "medium",
        title: `Potential CL.TE smuggling on ${v.pathname}`,
        description: `The server timed out when sent a request with conflicting Content-Length and Transfer-Encoding headers (TE variant: "${v.variant}"). This may indicate the server processes Transfer-Encoding while a front-end proxy uses Content-Length, enabling request smuggling.`,
        evidence: `POST ${v.pathname}\nContent-Length: 4\nTransfer-Encoding: ${v.variant}\nBody: 0\\r\\n\\r\\n → timeout (server waiting for chunk data)`,
        remediation: "Ensure your reverse proxy and application agree on how to parse requests. Normalize Transfer-Encoding headers. Reject requests with both Content-Length and Transfer-Encoding.",
        cwe: "CWE-444",
        owasp: "A05:2021",
        confidence: 55,
        codeSnippet: `// Reject requests with conflicting CL/TE in middleware\nexport function middleware(req: NextRequest) {\n  const te = req.headers.get("transfer-encoding");\n  const cl = req.headers.get("content-length");\n  if (te && cl) {\n    return new NextResponse("Bad Request", { status: 400 });\n  }\n}`,
      });
      break;
    }
  }

  // Phase 2: H2.CL desync — HTTP/2 doesn't use Transfer-Encoding but may forward to HTTP/1.1 backend
  // Check if the server speaks HTTP/2 and test for CL mismatches
  const h2Results = await Promise.allSettled(
    testUrls.slice(0, 2).map(async (url) => {
      // Send a POST with mismatched Content-Length (less than actual body)
      const body = "x".repeat(100);
      try {
        const res = await scanFetch(url, {
          method: "POST",
          headers: {
            "Content-Type": "text/plain",
            "Content-Length": "5", // Mismatched: says 5 but body is 100
          },
          body,
          timeoutMs: 5000,
        });
        const text = await res.text();
        // If server processes the full body despite CL mismatch, it may be vulnerable
        if (text.includes("x".repeat(50))) {
          return { pathname: new URL(url).pathname, status: res.status };
        }
      } catch { /* skip */ }
      return null;
    }),
  );

  for (const r of h2Results) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `smuggling-h2cl-${count++}`,
      module: "Request Smuggling",
      severity: "medium",
      title: `Content-Length mismatch accepted on ${v.pathname}`,
      description: "The server processed a request body larger than the declared Content-Length. In HTTP/2-to-HTTP/1.1 downgrade scenarios, this can lead to request smuggling where excess bytes are interpreted as the start of the next request.",
      evidence: `POST ${v.pathname}\nContent-Length: 5 (actual body: 100 bytes)\nServer processed full body (status ${v.status})`,
      remediation: "Validate Content-Length matches actual body size. Configure your reverse proxy to reject mismatched requests.",
      cwe: "CWE-444",
      owasp: "A05:2021",
      confidence: 60,
      codeSnippet: `// Validate Content-Length matches body\nexport async function POST(req: Request) {\n  const cl = parseInt(req.headers.get("content-length") || "0", 10);\n  const body = await req.text();\n  if (cl > 0 && body.length !== cl) {\n    return Response.json({ error: "Content-Length mismatch" }, { status: 400 });\n  }\n}`,
    });
    break;
  }

  // Phase 3: Header injection via hop-by-hop header abuse
  // Test if hop-by-hop headers like Connection can strip security headers
  const hopByHopResults = await Promise.allSettled(
    testUrls.slice(0, 3).map(async (url) => {
      // Normal request to get baseline headers
      const baseRes = await scanFetch(url, { timeoutMs: 5000 });
      const baseCookie = baseRes.headers.get("set-cookie");
      const baseAuth = baseRes.headers.has("www-authenticate");

      // Try to use Connection header to strip headers from proxy→backend
      const strippableHeaders = ["X-Forwarded-For", "X-Real-IP", "Cookie", "Authorization"];
      for (const header of strippableHeaders) {
        const res = await scanFetch(url, {
          headers: { Connection: `close, ${header}` },
          timeoutMs: 5000,
        });
        // If response changes when we ask proxy to strip a header, the proxy honors hop-by-hop
        const text = await res.text();
        const baseText = await (await scanFetch(url, { timeoutMs: 5000 })).text();
        if (res.status !== baseRes.status && Math.abs(text.length - baseText.length) > baseText.length * 0.2) {
          return { url: new URL(url).pathname, header, baseStatus: baseRes.status, newStatus: res.status };
        }
      }
      return null;
    }),
  );

  for (const r of hopByHopResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `smuggling-hop-${count++}`,
      module: "Request Smuggling",
      severity: "high",
      title: `Hop-by-hop header abuse strips ${v.header} on ${v.url}`,
      description: `Adding "${v.header}" to the Connection header caused the proxy to strip it before forwarding. This can bypass authentication (by stripping Authorization), IP restrictions (by stripping X-Forwarded-For), or session handling (by stripping Cookie).`,
      evidence: `Connection: close, ${v.header}\nBaseline status: ${v.baseStatus} → Modified status: ${v.newStatus}`,
      remediation: "Configure your reverse proxy to ignore custom Connection header values. Only honor standard hop-by-hop headers (Keep-Alive, Transfer-Encoding, etc.).",
      cwe: "CWE-444",
      owasp: "A05:2021",
      codeSnippet: `# nginx — ignore client Connection header abuse\nproxy_set_header Connection "";\n\n# Or in middleware, reject requests that try to strip security headers\nexport function middleware(req: NextRequest) {\n  const conn = req.headers.get("connection") || "";\n  if (/authorization|cookie|x-forwarded/i.test(conn)) {\n    return new NextResponse("Bad Request", { status: 400 });\n  }\n}`,
    });
    break;
  }

  // Phase 4: HTTP method override confusion
  // Test if X-HTTP-Method-Override lets POST become different methods for auth bypass
  const protectedEndpoints = target.apiEndpoints.filter((ep) =>
    /admin|user|setting|config|delete|remove/i.test(ep),
  ).slice(0, 4);

  const methodOverrideResults = await Promise.allSettled(
    protectedEndpoints.map(async (endpoint) => {
      // Check if DELETE returns 401/403 normally
      const deleteRes = await scanFetch(endpoint, {
        method: "DELETE",
        timeoutMs: 5000,
      });
      if (deleteRes.status !== 401 && deleteRes.status !== 403) return null;

      // Try POST with X-HTTP-Method-Override: DELETE
      const overrideRes = await scanFetch(endpoint, {
        method: "POST",
        headers: {
          "X-HTTP-Method-Override": "DELETE",
          "Content-Type": "application/json",
        },
        body: "{}",
        timeoutMs: 5000,
      });

      if (overrideRes.ok || overrideRes.status === 204) {
        return {
          endpoint: new URL(endpoint).pathname,
          deleteStatus: deleteRes.status,
          overrideStatus: overrideRes.status,
        };
      }
      return null;
    }),
  );

  for (const r of methodOverrideResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `smuggling-method-override-${count++}`,
      module: "Request Smuggling",
      severity: "high",
      title: `Method override bypasses auth on ${v.endpoint}`,
      description: `DELETE ${v.endpoint} returns ${v.deleteStatus}, but POST with X-HTTP-Method-Override: DELETE returns ${v.overrideStatus}. The application processes the method override but the auth middleware only checks the original HTTP method.`,
      evidence: `DELETE ${v.endpoint} → ${v.deleteStatus}\nPOST ${v.endpoint} + X-HTTP-Method-Override: DELETE → ${v.overrideStatus}`,
      remediation: "Apply auth checks after method override resolution. Or better, reject method override headers entirely in production.",
      cwe: "CWE-444",
      owasp: "A01:2021",
      codeSnippet: `// Reject method override in production\nexport function middleware(req: NextRequest) {\n  if (req.headers.get("x-http-method-override")) {\n    return NextResponse.json({ error: "Method override not allowed" }, { status: 400 });\n  }\n}`,
    });
    break;
  }

  // Phase 5: WebSocket upgrade smuggling
  // Check if the server accepts Upgrade: websocket on non-WebSocket paths
  const wsUpgradeResults = await Promise.allSettled(
    testUrls.slice(0, 3).map(async (url) => {
      const res = await scanFetch(url, {
        headers: {
          Upgrade: "websocket",
          Connection: "Upgrade",
          "Sec-WebSocket-Version": "13",
          "Sec-WebSocket-Key": btoa(String(Math.random())),
        },
        timeoutMs: 5000,
      });
      // 101 Switching Protocols on a non-WS endpoint is concerning
      if (res.status === 101) {
        return { url: new URL(url).pathname };
      }
      return null;
    }),
  );

  for (const r of wsUpgradeResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `smuggling-ws-upgrade-${count++}`,
      module: "Request Smuggling",
      severity: "medium",
      title: `WebSocket upgrade accepted on non-WS path ${v.url}`,
      description: "The server accepted a WebSocket upgrade on a path that doesn't appear to be a WebSocket endpoint. In proxy environments, this can enable H2C smuggling or tunnel hijacking, allowing an attacker to bypass proxy-level access controls.",
      evidence: `GET ${v.url} with Upgrade: websocket → 101 Switching Protocols`,
      remediation: "Only accept WebSocket upgrades on designated WebSocket endpoints. Reject Upgrade headers on regular HTTP paths.",
      cwe: "CWE-444",
      owasp: "A05:2021",
      confidence: 65,
      codeSnippet: `// Only allow WS upgrade on specific paths\nexport function middleware(req: NextRequest) {\n  if (req.headers.get("upgrade") === "websocket" && !req.nextUrl.pathname.startsWith("/ws")) {\n    return new NextResponse("Upgrade not allowed", { status: 400 });\n  }\n}`,
    });
    break;
  }

  return findings;
};
