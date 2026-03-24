import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

const PROTO_POLLUTION_PAYLOADS: { key: string; json: string }[] = [
  { key: "__proto__", json: '{"__proto__":{"polluted":true}}' },
  { key: "constructor.prototype", json: '{"constructor":{"prototype":{"polluted":true}}}' },
];

const MASS_ASSIGNMENT_FIELDS = [
  { role: "admin" },
  { isAdmin: true },
  { is_admin: true },
  { admin: true },
  { role: "superadmin" },
  { verified: true },
  { emailVerified: true },
];

const LARGE_RESPONSE_THRESHOLD = 50_000; // 50KB — likely over-fetching
const LARGE_ARRAY_THRESHOLD = 50; // arrays with 50+ items suggest missing pagination

export const apiSecurityModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  for (const endpoint of target.apiEndpoints.slice(0, 15)) {
    const contentType = await getContentType(endpoint);
    if (!contentType?.includes("json")) continue;

    // Test prototype pollution
    for (const { key, json } of PROTO_POLLUTION_PAYLOADS) {
      try {
        const res = await scanFetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: json,
        });

        if (!res.ok) continue;

        const text = await res.text();
        // If the server echoes back the proto keys or returns 200 with a body, it may be processing them
        if (text.includes("polluted") || text.includes(key)) {
          findings.push({
            id: `api-proto-pollution-${findings.length}`,
            module: "API Security",
            severity: "high",
            title: `Possible prototype pollution via ${key} on ${new URL(endpoint).pathname}`,
            description: `The API accepted and processed a JSON body containing "${key}". This can lead to prototype pollution, which may allow an attacker to modify application behavior, bypass security checks, or achieve remote code execution.`,
            evidence: `POST ${endpoint}\nPayload: ${json}\nResponse: ${text.substring(0, 300)}`,
            remediation: "Sanitize incoming JSON to strip __proto__ and constructor keys. Use Object.create(null) for lookup objects. Consider a library like secure-json-parse.",
            cwe: "CWE-1321",
            owasp: "A03:2021",
          });
          break; // one finding per endpoint is enough
        }
      } catch {
        // skip
      }
    }

    // Test over-fetching / large responses
    try {
      const res = await scanFetch(endpoint);
      if (!res.ok) continue;

      const text = await res.text();
      if (text.length < 10) continue;

      let data: unknown;
      try { data = JSON.parse(text); } catch { continue; }

      // Check response size — large responses suggest no field filtering
      if (text.length > LARGE_RESPONSE_THRESHOLD) {
        findings.push({
          id: `api-overfetch-${findings.length}`,
          module: "API Security",
          severity: "medium",
          title: `Possible over-fetching on ${new URL(endpoint).pathname}`,
          description: `This API endpoint returns ${(text.length / 1024).toFixed(1)}KB of data in a single response. This often means the server is returning full database records instead of selecting only needed fields, potentially exposing internal or sensitive fields.`,
          evidence: `GET ${endpoint}\nResponse size: ${text.length} bytes\nPreview: ${text.substring(0, 200)}...`,
          remediation: "Implement field selection — only return the fields the client needs. Use DTOs or serializers to control API output shape.",
          cwe: "CWE-213",
          owasp: "A01:2021",
        });
      }

      // Check for missing pagination
      const arr = Array.isArray(data) ? data : null;
      if (arr && arr.length >= LARGE_ARRAY_THRESHOLD) {
        findings.push({
          id: `api-no-pagination-${findings.length}`,
          module: "API Security",
          severity: "medium",
          title: `No pagination on ${new URL(endpoint).pathname} (${arr.length} items)`,
          description: `This endpoint returns ${arr.length} items in a single response with no apparent pagination. As data grows, this becomes a denial-of-service risk and can leak data an attacker shouldn't see in bulk.`,
          evidence: `GET ${endpoint}\nItems returned: ${arr.length}\nResponse size: ${text.length} bytes`,
          remediation: "Implement cursor or offset-based pagination. Enforce a maximum page size (e.g., 50-100 items). Add rate limiting.",
          cwe: "CWE-770",
          owasp: "A04:2021",
        });
      }
    } catch {
      // skip
    }

    // Test mass assignment
    try {
      // First do a GET to understand the shape
      const getRes = await scanFetch(endpoint);
      if (!getRes.ok) continue;
      const getText = await getRes.text();

      for (const extraFields of MASS_ASSIGNMENT_FIELDS.slice(0, 3)) {
        try {
          const res = await scanFetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ test: "vibeshield-scan", ...extraFields }),
          });

          if (!res.ok) continue;

          const text = await res.text();
          // Check if the privilege field appears in the response
          const fieldName = Object.keys(extraFields)[0];
          const fieldVal = String(Object.values(extraFields)[0]);

          if (text.includes(fieldName) && text.includes(fieldVal)) {
            // Verify it's not just echoing the request — check it looks like a stored/processed response
            let parsed: Record<string, unknown> | null = null;
            try { parsed = JSON.parse(text); } catch { /* skip */ }

            if (parsed && fieldName in parsed) {
              findings.push({
                id: `api-mass-assignment-${findings.length}`,
                module: "API Security",
                severity: "high",
                title: `Possible mass assignment on ${new URL(endpoint).pathname}`,
                description: `The API accepted and returned a privileged field "${fieldName}" set to "${fieldVal}". This suggests the endpoint blindly assigns all incoming fields to the data model, which could allow privilege escalation.`,
                evidence: `POST ${endpoint}\nPayload included: ${JSON.stringify(extraFields)}\nResponse contains "${fieldName}": ${text.substring(0, 300)}`,
                remediation: "Use an allowlist of accepted fields in your API handlers. Never pass raw request body directly to database create/update operations. Use DTOs or pick() to select only permitted fields.",
                cwe: "CWE-915",
                owasp: "A08:2021",
              });
              break;
            }
          }
        } catch {
          // skip
        }
      }
    } catch {
      // skip
    }
  }

  return findings;
};

async function getContentType(url: string): Promise<string | null> {
  try {
    const res = await scanFetch(url, { method: "HEAD" });
    return res.headers.get("content-type");
  } catch {
    // Fall back to GET
    try {
      const res = await scanFetch(url);
      return res.headers.get("content-type");
    } catch {
      return null;
    }
  }
}
