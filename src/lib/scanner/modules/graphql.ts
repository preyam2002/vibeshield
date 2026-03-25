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
            codeSnippet: `// Install: npm i graphql-depth-limit\nimport depthLimit from "graphql-depth-limit";\nconst server = new ApolloServer({\n  validationRules: [depthLimit(10)],\n});`,
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
            codeSnippet: `// Apollo Server — disable batching\nconst server = new ApolloServer({\n  allowBatchedHttpRequests: false,\n});`,
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
            codeSnippet: `// Install: npm i graphql-query-complexity\nimport { createComplexityLimitRule } from "graphql-validation-complexity";\nconst server = new ApolloServer({\n  validationRules: [createComplexityLimitRule(1000)],\n});`,
          });
        }
      } catch { /* skip */ }
    }

    // Test if arbitrary queries are accepted (no persisted query enforcement)
    // APQ-enabled servers should reject unknown query hashes
    try {
      const apqRes = await scanFetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          extensions: { persistedQuery: { version: 1, sha256Hash: "0".repeat(64) } },
        }),
        timeoutMs: 5000,
      });
      if (apqRes.ok) {
        const data = await apqRes.json() as { errors?: { message?: string }[] };
        const hasPersistedQueryError = data?.errors?.some((e) =>
          /persisted|not found|not registered|unknown hash/i.test(e?.message || ""),
        );
        // If the server returns a persisted query error, APQ is active — good
        // If it doesn't error at all with a fake hash, something is off but not actionable
        // The real check: can we send arbitrary queries WITHOUT a hash?
        if (hasPersistedQueryError) {
          // APQ is active, now test if arbitrary queries still work without extensions
          const arbitraryRes = await scanFetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ query: "{__typename}" }),
            timeoutMs: 5000,
          });
          if (arbitraryRes.ok) {
            const arbData = await arbitraryRes.json() as { data?: unknown; errors?: unknown[] };
            if (arbData?.data && !arbData?.errors) {
              endpointFindings.push({
                id: `graphql-apq-bypass-${endpoint}`,
                module: "GraphQL",
                severity: "low",
                title: "GraphQL accepts arbitrary queries alongside persisted queries",
                description: "While Automatic Persisted Queries (APQ) is enabled, the server also accepts arbitrary query strings. This means APQ provides caching benefits but not security hardening. Attackers can still send any query.",
                evidence: `APQ enabled (fake hash returned persisted query error)\nBut arbitrary query {__typename} also accepted at ${endpoint}`,
                remediation: "If using APQ for security, configure the server to reject non-persisted queries. In Apollo Server, use the persistedQueries plugin with onlyPersistedQueries option.",
                cwe: "CWE-284",
                codeSnippet: `// Apollo Server — enforce persisted queries only\nimport { ApolloServerPluginPersistedQueries } from '@apollo/server/plugin/persistedQueries';\nconst server = new ApolloServer({\n  plugins: [\n    ApolloServerPluginPersistedQueries({\n      onlyPersistedQueries: true,\n    }),\n  ],\n});`,
              });
            }
          }
        }
      }
    } catch { /* skip */ }

    // Test field suggestion leak (returns "Did you mean" hints even with introspection off)
    try {
      const suggestRes = await scanFetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: `{use}` }), // partial field name
        timeoutMs: 5000,
      });
      if (suggestRes.ok || suggestRes.status === 400) {
        const data = await suggestRes.json() as { errors?: { message?: string }[] };
        const suggestions = data?.errors?.filter((e) =>
          /did you mean|did you mean one of/i.test(e?.message || ""),
        );
        if (suggestions && suggestions.length > 0) {
          const suggestedFields = suggestions
            .flatMap((s) => s.message?.match(/"([^"]+)"/g) || [])
            .map((f) => f.replace(/"/g, ""));
          endpointFindings.push({
            id: `graphql-field-suggestions-${endpoint}`,
            module: "GraphQL",
            severity: "low",
            title: `GraphQL field suggestions leak schema info on ${new URL(endpoint).pathname}`,
            description: `The server returns "Did you mean" suggestions for mistyped fields. Even with introspection disabled, attackers can enumerate the schema by sending partial field names.`,
            evidence: `Query: {use}\nSuggested fields: ${suggestedFields.join(", ")}`,
            remediation: "Disable field suggestion hints in production. In Apollo Server, configure the validationRules to suppress suggestions.",
            cwe: "CWE-200",
            codeSnippet: `// Disable field suggestions in Apollo Server\nimport { NoSchemaIntrospectionCustomRule } from "graphql";\nconst server = new ApolloServer({\n  introspection: false,\n  // Custom validation rule to suppress "Did you mean" hints\n  formatError: (err) => ({\n    message: err.message.replace(/Did you mean.*$/, ""),\n    ...err,\n  }),\n});`,
          });
        }
      }
    } catch { /* skip */ }

    // Test GraphQL subscription endpoint (WebSocket-based real-time queries)
    try {
      const subRes = await scanFetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: `{__schema{subscriptionType{fields{name}}}}` }),
        timeoutMs: 5000,
      });
      if (subRes.ok) {
        const data = await subRes.json() as { data?: { __schema?: { subscriptionType?: { fields?: { name: string }[] } } } };
        const subscriptions = data?.data?.__schema?.subscriptionType?.fields;
        if (subscriptions && subscriptions.length > 0) {
          const sensitiveSubscriptions = subscriptions.filter((s) =>
            /admin|user|order|payment|message|notification|event|log/i.test(s.name),
          );
          if (sensitiveSubscriptions.length > 0) {
            endpointFindings.push({
              id: `graphql-subscriptions-${endpoint}`,
              module: "GraphQL",
              severity: "medium",
              title: `${subscriptions.length} GraphQL subscriptions exposed (${sensitiveSubscriptions.length} sensitive)`,
              description: `Found ${subscriptions.length} GraphQL subscription types. ${sensitiveSubscriptions.length} appear to expose sensitive real-time data: ${sensitiveSubscriptions.map((s) => s.name).join(", ")}. If subscriptions lack auth, attackers can monitor all events in real-time.`,
              evidence: `Subscriptions: ${subscriptions.map((s) => s.name).join(", ")}`,
              remediation: "Add authentication to GraphQL subscriptions. Validate the connection_init payload for a valid auth token.",
              cwe: "CWE-862", owasp: "A01:2021",
              codeSnippet: `// Authenticate GraphQL subscriptions (graphql-ws)\nimport { useServer } from "graphql-ws/lib/use/ws";\nuseServer({\n  onConnect: async (ctx) => {\n    const token = ctx.connectionParams?.authorization;\n    if (!token || !await verifyJWT(token)) return false;\n  },\n  schema,\n}, wsServer);`,
            });
          }
        }
      }
    } catch { /* skip */ }

    // Test if mutations are discoverable and accessible without auth
    try {
      const mutationProbe = await scanFetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: `{__schema{mutationType{fields{name}}}}` }),
        timeoutMs: 5000,
      });
      if (mutationProbe.ok) {
        const data = await mutationProbe.json() as { data?: { __schema?: { mutationType?: { fields?: { name: string }[] } } } };
        const mutations = data?.data?.__schema?.mutationType?.fields;
        if (mutations && mutations.length > 0) {
          const dangerousMutations = mutations.filter((m) =>
            /delete|remove|destroy|drop|reset|admin|grant|revoke|update.*role|set.*password/i.test(m.name),
          );
          if (dangerousMutations.length > 0) {
            endpointFindings.push({
              id: `graphql-dangerous-mutations-${endpoint}`,
              module: "GraphQL",
              severity: "high",
              title: `${dangerousMutations.length} dangerous GraphQL mutations exposed`,
              description: `Found ${mutations.length} mutations via introspection, including ${dangerousMutations.length} that appear destructive or privileged: ${dangerousMutations.map((m) => m.name).slice(0, 5).join(", ")}. If these lack proper authorization, attackers can modify or delete data.`,
              evidence: `Dangerous mutations: ${dangerousMutations.map((m) => m.name).join(", ")}\nTotal mutations: ${mutations.length}`,
              remediation: "Add authentication and authorization checks to all mutations. Disable introspection to prevent mutation discovery.",
              cwe: "CWE-862",
              owasp: "A01:2021",
              codeSnippet: `// Protect mutations with auth middleware\nconst resolvers = {\n  Mutation: {\n    deleteUser: async (_, args, context) => {\n      if (!context.user?.isAdmin) throw new Error("Unauthorized");\n      // ...\n    },\n  },\n};`,
            });
          }
        }
      }
    } catch { /* skip */ }

    return endpointFindings;
  });

  const results = await Promise.allSettled(endpointTests);
  for (const r of results) {
    if (r.status === "fulfilled") findings.push(...r.value);
  }

  return findings;
};
