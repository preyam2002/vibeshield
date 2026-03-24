import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

const GRAPHQL_PATHS = [
  "/graphql", "/api/graphql", "/graphql/v1", "/gql",
  "/query", "/api/query", "/v1/graphql",
];

const INTROSPECTION_QUERY = JSON.stringify({
  query: `{__schema{types{name fields{name type{name}}}}}`,
});

export const graphqlModule: ScanModule = async (target) => {
  const findings: Finding[] = [];

  // Find GraphQL endpoints
  const graphqlEndpoints: string[] = [];

  for (const path of GRAPHQL_PATHS) {
    const url = target.baseUrl + path;
    try {
      const res = await scanFetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: INTROSPECTION_QUERY,
      });
      if (res.ok) {
        const data = await res.json() as { data?: { __schema?: { types?: unknown[] } } };
        if (data?.data?.__schema) {
          graphqlEndpoints.push(url);
        }
      }
    } catch {
      // skip
    }
  }

  // Also check endpoints discovered during recon
  for (const ep of target.apiEndpoints) {
    if (/graphql|gql/i.test(ep) && !graphqlEndpoints.includes(ep)) {
      graphqlEndpoints.push(ep);
    }
  }

  for (const endpoint of graphqlEndpoints) {
    // Test introspection
    try {
      const res = await scanFetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: INTROSPECTION_QUERY,
      });

      if (res.ok) {
        const data = await res.json() as { data?: { __schema?: { types?: { name: string; fields?: { name: string }[] }[] } } };
        const schema = data?.data?.__schema;
        if (schema?.types) {
          const userTypes = schema.types.filter(
            (t: { name: string }) => !t.name.startsWith("__") && !["String", "Int", "Float", "Boolean", "ID"].includes(t.name),
          );
          const sensitiveTypes = userTypes.filter((t: { name: string; fields?: { name: string }[] }) =>
            t.fields?.some((f: { name: string }) => /password|secret|token|key|ssn|credit/i.test(f.name)),
          );

          findings.push({
            id: `graphql-introspection-${findings.length}`,
            module: "GraphQL",
            severity: "high",
            title: `GraphQL introspection enabled on ${new URL(endpoint).pathname}`,
            description: `Introspection is enabled, exposing your entire API schema. Found ${userTypes.length} custom types.${sensitiveTypes.length > 0 ? ` ${sensitiveTypes.length} types contain sensitive-looking fields.` : ""}`,
            evidence: `Types: ${userTypes.map((t: { name: string }) => t.name).slice(0, 10).join(", ")}${sensitiveTypes.length > 0 ? `\nSensitive types: ${sensitiveTypes.map((t: { name: string }) => t.name).join(", ")}` : ""}`,
            remediation: "Disable introspection in production. For Apollo Server: new ApolloServer({ introspection: false })",
            cwe: "CWE-200",
            owasp: "A05:2021",
          });
        }
      }
    } catch {
      // skip
    }

    // Test for query depth limit
    const deepQuery = JSON.stringify({
      query: `{__schema{types{fields{type{fields{type{fields{type{name}}}}}}}}}`,
    });
    try {
      const res = await scanFetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: deepQuery,
      });
      if (res.ok) {
        const data = await res.json() as { data?: unknown; errors?: unknown[] };
        // Only flag if the deep query actually succeeded (not rejected by depth limiter)
        if (data?.data && !data?.errors) {
          findings.push({
            id: `graphql-no-depth-limit-${findings.length}`,
            module: "GraphQL",
            severity: "medium",
            title: "No GraphQL query depth limit",
            description: "Deeply nested queries are accepted. Attackers can craft expensive queries that cause denial of service.",
            evidence: `Deeply nested query accepted at ${endpoint}`,
            remediation: "Implement query depth limiting (max depth 7-10). Use graphql-depth-limit or similar.",
            cwe: "CWE-400",
          });
        }
      }
    } catch {
      // skip
    }

    // Test batch query (DoS vector)
    const batchQuery = JSON.stringify(
      Array.from({ length: 20 }, () => ({ query: `{__typename}` })),
    );
    try {
      const res = await scanFetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: batchQuery,
      });
      if (res.ok) {
        const data = await res.json();
        if (Array.isArray(data) && data.length >= 10) {
          findings.push({
            id: `graphql-batch-${findings.length}`,
            module: "GraphQL",
            severity: "medium",
            title: "GraphQL batch queries allowed",
            description: `The server accepts batch queries (tested with 20). Attackers can send thousands of operations in a single request to bypass rate limiting.`,
            evidence: `Batch of 20 queries accepted, ${data.length} responses returned`,
            remediation: "Disable or limit batch queries. Set a maximum batch size of 5-10.",
            cwe: "CWE-400",
          });
        }
      }
    } catch {
      // skip
    }
  }

  return findings;
};
