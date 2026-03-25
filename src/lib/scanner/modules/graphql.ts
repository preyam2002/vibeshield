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

  // Discover GraphQL endpoints in parallel
  const discoveryResults = await Promise.allSettled(
    GRAPHQL_PATHS.map(async (path) => {
      const url = target.baseUrl + path;
      const res = await scanFetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: INTROSPECTION_QUERY,
        timeoutMs: 5000,
      });
      if (!res.ok) return null;
      const data = await res.json() as { data?: { __schema?: unknown } };
      return data?.data?.__schema ? url : null;
    }),
  );

  const graphqlEndpoints: string[] = [];
  for (const r of discoveryResults) {
    if (r.status === "fulfilled" && r.value) graphqlEndpoints.push(r.value);
  }

  // Also check recon-discovered endpoints
  for (const ep of target.apiEndpoints) {
    if (/graphql|gql/i.test(ep) && !graphqlEndpoints.includes(ep)) {
      graphqlEndpoints.push(ep);
    }
  }

  // Test each endpoint in parallel
  const endpointTests = graphqlEndpoints.map(async (endpoint) => {
    const endpointFindings: Finding[] = [];

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
            (t) => !t.name.startsWith("__") && !["String", "Int", "Float", "Boolean", "ID"].includes(t.name),
          );
          const sensitiveTypes = userTypes.filter((t) =>
            t.fields?.some((f) => /password|secret|token|key|ssn|credit/i.test(f.name)),
          );

          endpointFindings.push({
            id: `graphql-introspection-${endpoint}`,
            module: "GraphQL",
            severity: "high",
            title: `GraphQL introspection enabled on ${new URL(endpoint).pathname}`,
            description: `Introspection is enabled, exposing your entire API schema. Found ${userTypes.length} custom types.${sensitiveTypes.length > 0 ? ` ${sensitiveTypes.length} types contain sensitive-looking fields.` : ""}`,
            evidence: `Types: ${userTypes.map((t) => t.name).slice(0, 10).join(", ")}${sensitiveTypes.length > 0 ? `\nSensitive types: ${sensitiveTypes.map((t) => t.name).join(", ")}` : ""}`,
            remediation: "Disable introspection in production. For Apollo Server: new ApolloServer({ introspection: false })",
            cwe: "CWE-200",
            owasp: "A05:2021",
            codeSnippet: `// Apollo Server\nconst server = new ApolloServer({\n  typeDefs, resolvers,\n  introspection: false, // disable in production\n});\n\n// Yoga / Envelop\nuseDisableIntrospection()`,
          });
        }
      }
    } catch { /* skip */ }

    // Test depth limit, batch queries, and alias abuse in parallel
    const [depthRes, batchRes, aliasRes] = await Promise.allSettled([
      // Depth limit test
      scanFetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: `{__schema{types{fields{type{fields{type{fields{type{name}}}}}}}}}` }),
      }),
      // Batch query test
      scanFetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(Array.from({ length: 20 }, () => ({ query: `{__typename}` }))),
      }),
      // Alias abuse test — 50 aliased fields in a single query
      scanFetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: `{${Array.from({ length: 50 }, (_, i) => `a${i}:__typename`).join(" ")}}` }),
      }),
    ]);

    if (depthRes.status === "fulfilled" && depthRes.value.ok) {
      try {
        const data = await depthRes.value.json() as { data?: unknown; errors?: unknown[] };
        if (data?.data && !data?.errors) {
          endpointFindings.push({
            id: `graphql-no-depth-limit-${endpoint}`,
            module: "GraphQL",
            severity: "medium",
            title: "No GraphQL query depth limit",
            description: "Deeply nested queries are accepted. Attackers can craft expensive queries that cause denial of service.",
            evidence: `Deeply nested query accepted at ${endpoint}`,
            remediation: "Implement query depth limiting (max depth 7-10). Use graphql-depth-limit or similar.",
            cwe: "CWE-400",
          });
        }
      } catch { /* skip */ }
    }

    if (batchRes.status === "fulfilled" && batchRes.value.ok) {
      try {
        const data = await batchRes.value.json();
        if (Array.isArray(data) && data.length >= 10) {
          endpointFindings.push({
            id: `graphql-batch-${endpoint}`,
            module: "GraphQL",
            severity: "medium",
            title: "GraphQL batch queries allowed",
            description: `The server accepts batch queries (tested with 20). Attackers can send thousands of operations in a single request to bypass rate limiting.`,
            evidence: `Batch of 20 queries accepted, ${data.length} responses returned`,
            remediation: "Disable or limit batch queries. Set a maximum batch size of 5-10.",
            cwe: "CWE-400",
          });
        }
      } catch { /* skip */ }
    }

    if (aliasRes.status === "fulfilled" && aliasRes.value.ok) {
      try {
        const data = await aliasRes.value.json() as { data?: Record<string, unknown>; errors?: unknown[] };
        const aliasCount = data?.data ? Object.keys(data.data).length : 0;
        if (aliasCount >= 40 && !data?.errors) {
          endpointFindings.push({
            id: `graphql-alias-abuse-${endpoint}`,
            module: "GraphQL",
            severity: "medium",
            title: "No GraphQL alias limit",
            description: `The server accepts queries with ${aliasCount} aliased fields. Attackers can use aliases to multiply query cost and bypass per-field rate limits.`,
            evidence: `Query with 50 aliases accepted, ${aliasCount} fields returned at ${endpoint}`,
            remediation: "Implement alias limits or query cost analysis. Libraries like graphql-query-complexity can help.",
            cwe: "CWE-400",
          });
        }
      } catch { /* skip */ }
    }

    return endpointFindings;
  });

  const results = await Promise.allSettled(endpointTests);
  for (const r of results) {
    if (r.status === "fulfilled") findings.push(...r.value);
  }

  return findings;
};
