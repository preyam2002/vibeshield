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

    // ── Phase: Field suggestion exploitation ──
    // Send queries with intentional typos targeting common sensitive field names
    // to extract real field names from "Did you mean" error messages
    const typoProbes = [
      { query: `{pasword}`, target: "password" },
      { query: `{emai}`, target: "email" },
      { query: `{secre}`, target: "secret" },
      { query: `{toke}`, target: "token" },
      { query: `{admi}`, target: "admin" },
      { query: `{balanc}`, target: "balance" },
      { query: `{accoun}`, target: "account" },
      { query: `{credi}`, target: "credit" },
      { query: `{phon}`, target: "phone" },
      { query: `{addres}`, target: "address" },
    ];
    try {
      const typoResults = await Promise.allSettled(
        typoProbes.map(async (probe) => {
          const res = await scanFetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ query: probe.query }),
            timeoutMs: 5000,
          });
          if (!res.ok && res.status !== 400) return null;
          const data = await res.json() as { errors?: { message?: string }[] };
          const suggestions = data?.errors
            ?.map((e) => e?.message || "")
            .filter((m) => /did you mean/i.test(m));
          if (!suggestions || suggestions.length === 0) return null;
          const leaked = suggestions
            .flatMap((s) => s.match(/"([^"]+)"/g) || [])
            .map((f) => f.replace(/"/g, ""));
          return leaked.length > 0 ? { probe: probe.query, target: probe.target, leaked } : null;
        }),
      );

      const leakedFields: { probe: string; target: string; leaked: string[] }[] = [];
      for (const r of typoResults) {
        if (r.status === "fulfilled" && r.value) leakedFields.push(r.value);
      }

      if (leakedFields.length >= 2) {
        const allLeaked = Array.from(new Set(leakedFields.flatMap((l) => l.leaked)));
        endpointFindings.push({
          id: `graphql-field-suggestion-exploit-${endpoint}`,
          module: "graphql",
          severity: "medium",
          title: `GraphQL field names extractable via suggestion exploitation on ${new URL(endpoint).pathname}`,
          description: `Sending queries with intentional typos reveals real field names through "Did you mean" error messages. ${leakedFields.length} probes returned field suggestions, leaking ${allLeaked.length} field names. Attackers can enumerate the entire schema even with introspection disabled.`,
          evidence: `Probes and leaked fields:\n${leakedFields.map((l) => `  ${l.probe} → ${l.leaked.join(", ")}`).join("\n")}`,
          remediation: "Disable field suggestion messages in production. In graphql-js, set the `customFormatErrorFn` to strip suggestion text. In Apollo Server, use a plugin to sanitize error messages.",
          cwe: "CWE-200",
          codeSnippet: `// Apollo Server — strip field suggestions from errors\nconst server = new ApolloServer({\n  formatError: (err) => {\n    const msg = err.message.replace(/Did you mean.*$/is, "").trim();\n    return { ...err, message: msg || "Validation error" };\n  },\n});`,
        });
      }
    } catch { /* skip */ }

    // ── Phase: Batch query abuse ──
    // Test sending an array of mixed queries to bypass rate limiting or extract data in bulk
    try {
      const batchPayload = [
        { query: `{__typename}` },
        { query: `{__schema{queryType{name}}}` },
        { query: `{__schema{mutationType{name}}}` },
        { query: `{__schema{subscriptionType{name}}}` },
        { query: `{__schema{types{name}}}` },
        ...Array.from({ length: 45 }, (_, i) => ({ query: `{a${i}:__typename}` })),
      ];
      const batchAbuseRes = await scanFetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(batchPayload),
        timeoutMs: 8000,
      });
      if (batchAbuseRes.ok) {
        const data = await batchAbuseRes.json();
        if (Array.isArray(data) && data.length >= 40) {
          const schemaLeaks = data.filter(
            (d: { data?: { __schema?: unknown } }) => d?.data?.__schema,
          );
          endpointFindings.push({
            id: `graphql-batch-abuse-${endpoint}`,
            module: "graphql",
            severity: "high",
            title: `GraphQL batch query abuse possible (${data.length} ops accepted) on ${new URL(endpoint).pathname}`,
            description: `The server accepted a batch of ${batchPayload.length} queries and returned ${data.length} responses. ${schemaLeaks.length > 0 ? `${schemaLeaks.length} responses contained schema data. ` : ""}Attackers can bypass per-request rate limiting by packing thousands of operations into a single HTTP request, enabling brute-force attacks and bulk data extraction.`,
            evidence: `Sent ${batchPayload.length} queries in a single request, received ${data.length} responses.${schemaLeaks.length > 0 ? ` ${schemaLeaks.length} leaked schema info.` : ""}`,
            remediation: "Limit the maximum batch size to 5-10 operations. Apply rate limiting per operation, not per HTTP request. In Apollo Server, set `allowBatchedHttpRequests: false` or configure a batch limit plugin.",
            cwe: "CWE-799",
            codeSnippet: `// Apollo Server v4 — disable batching\nconst server = new ApolloServer({\n  allowBatchedHttpRequests: false,\n});\n\n// Or limit batch size with a plugin\nconst batchLimitPlugin = {\n  async requestDidStart() {\n    return {\n      async didResolveOperation(ctx) {\n        if (ctx.request.http?.body && Array.isArray(JSON.parse(ctx.request.http.body))) {\n          const batch = JSON.parse(ctx.request.http.body);\n          if (batch.length > 5) throw new Error("Batch size exceeds limit");\n        }\n      },\n    };\n  },\n};`,
          });
        }
      }
    } catch { /* skip */ }

    // ── Phase: Mutation discovery via probing ──
    // Probe for common mutations without relying on introspection
    const mutationProbes = [
      { name: "createUser", query: `mutation{createUser{__typename}}` },
      { name: "updateUser", query: `mutation{updateUser{__typename}}` },
      { name: "deleteUser", query: `mutation{deleteUser{__typename}}` },
      { name: "login", query: `mutation{login{__typename}}` },
      { name: "register", query: `mutation{register{__typename}}` },
      { name: "resetPassword", query: `mutation{resetPassword{__typename}}` },
      { name: "updateRole", query: `mutation{updateRole{__typename}}` },
      { name: "createAdmin", query: `mutation{createAdmin{__typename}}` },
      { name: "deleteAccount", query: `mutation{deleteAccount{__typename}}` },
      { name: "updateSettings", query: `mutation{updateSettings{__typename}}` },
    ];
    try {
      const mutationResults = await Promise.allSettled(
        mutationProbes.map(async (probe) => {
          const res = await scanFetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ query: probe.query }),
            timeoutMs: 5000,
          });
          if (!res.ok && res.status !== 400) return null;
          const data = await res.json() as { data?: unknown; errors?: { message?: string }[] };
          // A mutation exists if we get argument errors, type errors, or actual data —
          // but NOT "field not found" / "cannot query" errors
          const errors = data?.errors?.map((e) => e?.message || "") || [];
          const notFound = errors.some((m) =>
            /cannot query|field.*not found|unknown field|not exist/i.test(m),
          );
          if (notFound) return null;
          // If we got data back or got argument/type errors, the mutation exists
          const exists = data?.data !== undefined || errors.some((m) =>
            /argument|variable|required|type/i.test(m),
          );
          return exists ? probe.name : null;
        }),
      );

      const discoveredMutations: string[] = [];
      for (const r of mutationResults) {
        if (r.status === "fulfilled" && r.value) discoveredMutations.push(r.value);
      }

      if (discoveredMutations.length > 0) {
        const dangerous = discoveredMutations.filter((m) =>
          /delete|reset|admin|role|create.*admin/i.test(m),
        );
        endpointFindings.push({
          id: `graphql-mutation-discovery-${endpoint}`,
          module: "graphql",
          severity: dangerous.length > 0 ? "high" : "medium",
          title: `${discoveredMutations.length} GraphQL mutations discoverable via probing on ${new URL(endpoint).pathname}`,
          description: `Probing for common mutation names revealed ${discoveredMutations.length} existing mutations: ${discoveredMutations.join(", ")}. ${dangerous.length > 0 ? `${dangerous.length} are potentially dangerous: ${dangerous.join(", ")}. ` : ""}These mutations are accessible without introspection, meaning attackers can discover and invoke them by guessing names.`,
          evidence: `Discovered mutations: ${discoveredMutations.join(", ")}\n${dangerous.length > 0 ? `Dangerous mutations: ${dangerous.join(", ")}` : ""}`,
          remediation: "Require authentication and authorization for all mutations. Use persisted queries to prevent arbitrary mutation execution. Return generic error messages that do not confirm whether a mutation exists.",
          cwe: "CWE-862",
          codeSnippet: `// Protect mutations with auth middleware\nconst authDirective = (next, src, args, ctx) => {\n  if (!ctx.user) throw new AuthenticationError("Not authenticated");\n  return next();\n};\n\n// Use persisted queries to block arbitrary mutations\nconst server = new ApolloServer({\n  persistedQueries: { onlyPersistedQueries: true },\n});`,
        });
      }
    } catch { /* skip */ }

    // ── Phase: Subscription endpoint exposure ──
    // Check if WebSocket subscriptions are accessible without authentication
    try {
      const wsProtocols = ["ws", "wss"];
      const subPaths = ["/graphql", "/subscriptions", "/ws", "/graphql/ws"];
      const subEndpointUrl = new URL(endpoint);

      // Test subscription via HTTP upgrade hint and subscription query
      const [subQueryRes, subSchemaRes] = await Promise.allSettled([
        scanFetch(endpoint, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Upgrade": "websocket",
            "Connection": "Upgrade",
          },
          body: JSON.stringify({ query: `subscription{__typename}` }),
          timeoutMs: 5000,
        }),
        scanFetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            query: `{__schema{subscriptionType{name fields{name args{name type{name}}}}}}`,
          }),
          timeoutMs: 5000,
        }),
      ]);

      let subscriptionFields: { name: string }[] = [];
      let wsUpgradeHint = false;

      if (subQueryRes.status === "fulfilled") {
        const res = subQueryRes.value;
        if (res.status === 101 || res.headers.get("upgrade")?.toLowerCase() === "websocket") {
          wsUpgradeHint = true;
        }
      }

      if (subSchemaRes.status === "fulfilled" && subSchemaRes.value.ok) {
        const data = await subSchemaRes.value.json() as {
          data?: { __schema?: { subscriptionType?: { name: string; fields?: { name: string; args?: { name: string }[] }[] } } };
        };
        subscriptionFields = data?.data?.__schema?.subscriptionType?.fields || [];
      }

      if (wsUpgradeHint || subscriptionFields.length > 0) {
        const sensitiveSubs = subscriptionFields.filter((s) =>
          /message|notification|order|payment|user|event|admin|log|chat|transaction/i.test(s.name),
        );
        endpointFindings.push({
          id: `graphql-subscription-exposure-${endpoint}`,
          module: "graphql",
          severity: sensitiveSubs.length > 0 ? "high" : "medium",
          title: `GraphQL subscription endpoint exposed${subscriptionFields.length > 0 ? ` with ${subscriptionFields.length} subscriptions` : ""} on ${new URL(endpoint).pathname}`,
          description: `${wsUpgradeHint ? "The endpoint accepts WebSocket upgrade requests. " : ""}${subscriptionFields.length > 0 ? `Found ${subscriptionFields.length} subscription fields${sensitiveSubs.length > 0 ? `, including ${sensitiveSubs.length} sensitive ones: ${sensitiveSubs.map((s) => s.name).join(", ")}` : ""}. ` : ""}Unauthenticated WebSocket subscriptions allow attackers to monitor real-time data streams including user activity, messages, and transactions.`,
          evidence: `${wsUpgradeHint ? "WebSocket upgrade supported\n" : ""}${subscriptionFields.length > 0 ? `Subscription fields: ${subscriptionFields.map((s) => s.name).join(", ")}` : "Subscription type detected"}`,
          remediation: "Authenticate WebSocket connections during the connection_init phase. Reject subscription connections without valid tokens. Implement per-subscription authorization checks.",
          cwe: "CWE-306",
          codeSnippet: `// graphql-ws — authenticate on connection\nimport { useServer } from "graphql-ws/lib/use/ws";\nuseServer({\n  onConnect: async (ctx) => {\n    const token = ctx.connectionParams?.authToken;\n    if (!token) return false; // reject unauthenticated\n    const user = await verifyToken(token);\n    if (!user) return false;\n    ctx.extra.user = user;\n  },\n  onSubscribe: (ctx, msg) => {\n    if (!ctx.extra.user) throw new Error("Not authenticated");\n  },\n  schema,\n}, wsServer);`,
        });
      }
    } catch { /* skip */ }

    // ── Phase: Overly verbose error messages ──
    // Send malformed queries to trigger errors and check for stack traces or internal details
    const errorProbes = [
      { label: "syntax error", body: JSON.stringify({ query: `{{{` }) },
      { label: "type error", body: JSON.stringify({ query: `{__typename(invalid:true)}` }) },
      { label: "invalid operation", body: JSON.stringify({ query: `mutation{__typename}`, operationName: "NonExistent" }) },
      { label: "malformed JSON", body: `{"query": {{{INVALID` },
      { label: "null query", body: JSON.stringify({ query: null }) },
    ];
    try {
      const errorResults = await Promise.allSettled(
        errorProbes.map(async (probe) => {
          const res = await scanFetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: probe.body,
            timeoutMs: 5000,
          });
          const text = await res.text();
          let parsed: { errors?: { message?: string; extensions?: Record<string, unknown> }[] } | null = null;
          try { parsed = JSON.parse(text); } catch { /* raw text response */ }

          const indicators: string[] = [];
          const fullText = text.toLowerCase();

          if (/stack\s*trace|at\s+\w+\s*\(|\.js:\d+:\d+|\.ts:\d+:\d+/i.test(text)) indicators.push("stack trace");
          if (/node_modules|\/usr\/|\/home\/|\/app\/src\//i.test(text)) indicators.push("file paths");
          if (/postgresql|mysql|mongodb|redis|sequelize|prisma|typeorm/i.test(text)) indicators.push("database details");
          if (/internal server error.*detail|exception|traceback/i.test(text)) indicators.push("exception details");
          if (/version.*\d+\.\d+|express|koa|fastify|apollo.*server/i.test(fullText)) indicators.push("server/framework version");

          // Check extensions for debug info
          if (parsed?.errors) {
            for (const err of parsed.errors) {
              if (err.extensions) {
                const extKeys = Object.keys(err.extensions);
                if (extKeys.some((k) => /stack|trace|debug|exception|detail/i.test(k))) {
                  indicators.push("debug extensions");
                }
              }
            }
          }

          return indicators.length > 0 ? { probe: probe.label, indicators, sample: text.slice(0, 300) } : null;
        }),
      );

      const verboseErrors: { probe: string; indicators: string[]; sample: string }[] = [];
      for (const r of errorResults) {
        if (r.status === "fulfilled" && r.value) verboseErrors.push(r.value);
      }

      if (verboseErrors.length > 0) {
        const allIndicators = Array.from(new Set(verboseErrors.flatMap((v) => v.indicators)));
        endpointFindings.push({
          id: `graphql-verbose-errors-${endpoint}`,
          module: "graphql",
          severity: allIndicators.some((i) => /stack trace|database|file paths/.test(i)) ? "high" : "medium",
          title: `GraphQL endpoint returns overly verbose error messages on ${new URL(endpoint).pathname}`,
          description: `Sending malformed queries reveals internal details. ${verboseErrors.length} of ${errorProbes.length} error probes returned sensitive information including: ${allIndicators.join(", ")}. Verbose errors help attackers understand the server technology, file structure, and database in use.`,
          evidence: `Probes with verbose responses:\n${verboseErrors.map((v) => `  [${v.probe}] → leaked: ${v.indicators.join(", ")}\n    Sample: ${v.sample.slice(0, 150)}...`).join("\n")}`,
          remediation: "Sanitize all error messages in production. Remove stack traces, file paths, and database details from GraphQL error responses. Use a custom formatError function to return generic error messages.",
          cwe: "CWE-209",
          codeSnippet: `// Apollo Server — sanitize error messages\nconst server = new ApolloServer({\n  formatError: (formattedError, error) => {\n    // Log full error internally\n    console.error(error);\n    // Return sanitized error to client\n    if (formattedError.extensions?.code === "INTERNAL_SERVER_ERROR") {\n      return { message: "Internal server error", extensions: { code: "INTERNAL_SERVER_ERROR" } };\n    }\n    // Strip stack traces and paths\n    const { extensions, ...rest } = formattedError;\n    const { stacktrace, ...safeExt } = extensions || {};\n    return { ...rest, extensions: safeExt };\n  },\n  includeStacktraceInErrorResponses: false, // Apollo v4\n});`,
        });
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
