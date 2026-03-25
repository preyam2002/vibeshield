import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

const COMMON_TABLES = [
  "users", "profiles", "accounts", "auth.users",
  "posts", "comments", "messages", "notifications",
  "orders", "payments", "subscriptions", "invoices",
  "products", "items", "categories",
  "settings", "configs", "secrets",
  "files", "uploads", "documents",
  "sessions", "tokens", "api_keys",
  "teams", "organizations", "memberships",
  "logs", "events", "analytics",
];

export const supabaseModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const allJs = Array.from(target.jsContents.values()).join("\n");

  // Extract Supabase URL and anon key
  const urlMatch = allJs.match(/https:\/\/([a-z0-9]+)\.supabase\.co/);
  if (!urlMatch) return findings;

  const supabaseUrl = urlMatch[0];

  // Find anon key (JWT that starts with eyJ)
  const keyMatches = allJs.match(/eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g);
  if (!keyMatches || keyMatches.length === 0) return findings;

  // Try to determine which is anon vs service role by decoding
  let anonKey: string | null = null;
  let serviceRoleKey: string | null = null;

  for (const key of keyMatches) {
    try {
      const payload = JSON.parse(Buffer.from(key.split(".")[1], "base64url").toString());
      if (payload.role === "anon") anonKey = key;
      if (payload.role === "service_role") {
        serviceRoleKey = key;
        findings.push({
          id: "supabase-service-role-exposed",
          module: "Supabase",
          severity: "critical",
          title: "Supabase service_role key exposed in client code",
          description: "The service_role key bypasses ALL Row Level Security policies. Anyone can read, write, and delete ALL data in your database.",
          evidence: `Key role: service_role\nSupabase URL: ${supabaseUrl}`,
          remediation: "Remove the service_role key from client code IMMEDIATELY. Regenerate it in the Supabase dashboard. Only the anon key should be client-side.",
          cwe: "CWE-798",
          owasp: "A07:2021",
          codeSnippet: `// Only use anon key client-side\nconst supabase = createClient(\n  process.env.NEXT_PUBLIC_SUPABASE_URL!,\n  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY! // NOT service_role!\n);\n\n// Use service_role only on the server\n// app/api/admin/route.ts\nimport { createClient } from "@supabase/supabase-js";\nconst admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!);`,
        });
      }
    } catch {
      anonKey = key; // assume anon if can't decode
    }
  }

  const testKey = anonKey || keyMatches[0];

  // Test RLS on common tables using the REST API
  const tableResults = await Promise.allSettled(
    COMMON_TABLES.map(async (table) => {
      const res = await scanFetch(
        `${supabaseUrl}/rest/v1/${table}?select=*&limit=5`,
        {
          headers: {
            apikey: testKey,
            Authorization: `Bearer ${testKey}`,
          },
        },
      );
      const status = res.status;
      let data: unknown = null;
      let rowCount = 0;
      const contentRange = res.headers.get("content-range");

      if (status === 200) {
        data = await res.json();
        if (Array.isArray(data)) rowCount = data.length;
      }

      return { table, status, rowCount, contentRange, data };
    }),
  );

  for (const r of tableResults) {
    if (r.status !== "fulfilled") continue;
    const { table, status, rowCount, contentRange } = r.value;

    if (status === 200 && rowCount > 0) {
      const totalMatch = contentRange?.match(/\/(\d+|\*)/);
      const total = totalMatch ? totalMatch[1] : "unknown";

      findings.push({
        id: `supabase-rls-read-${table}`,
        module: "Supabase",
        severity: "critical",
        title: `Table "${table}" is readable with anon key (RLS bypass)`,
        description: `The "${table}" table returned ${rowCount} rows using only the anon key. Total rows: ${total}. Anyone can read this data without authentication.`,
        evidence: `GET ${supabaseUrl}/rest/v1/${table}?select=*&limit=5\nStatus: 200\nRows returned: ${rowCount}\nTotal: ${total}`,
        remediation: `Add RLS policies to the "${table}" table:\n1. ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY;\n2. CREATE POLICY "Users can only see own data" ON ${table} FOR SELECT USING (auth.uid() = user_id);`,
        cwe: "CWE-862",
        owasp: "A01:2021",
        codeSnippet: `-- Run in Supabase SQL Editor:\nALTER TABLE ${table} ENABLE ROW LEVEL SECURITY;\n\nCREATE POLICY "Users read own data"\n  ON ${table} FOR SELECT\n  USING (auth.uid() = user_id);\n\nCREATE POLICY "Users insert own data"\n  ON ${table} FOR INSERT\n  WITH CHECK (auth.uid() = user_id);`,
      });
    }
  }

  // Test write access, delete access, auth settings, and storage in parallel
  const [writeResults, deleteResults, authResult, storageResult] = await Promise.all([
    // Write access tests in parallel
    Promise.allSettled(
      ["users", "profiles", "posts", "comments"].map(async (table) => {
        const res = await scanFetch(`${supabaseUrl}/rest/v1/${table}`, {
          method: "POST",
          headers: { apikey: testKey, Authorization: `Bearer ${testKey}`, "Content-Type": "application/json", Prefer: "return=minimal" },
          body: JSON.stringify({ _vibeshield_test: true }),
        });
        if (res.status === 201 || res.status === 409) return { table, status: res.status };
        return null;
      }),
    ),
    // DELETE access tests — check if anon can delete (uses impossible filter so nothing is actually deleted)
    Promise.allSettled(
      ["users", "profiles", "posts", "orders"].map(async (table) => {
        const res = await scanFetch(`${supabaseUrl}/rest/v1/${table}?id=eq.00000000-0000-0000-0000-000000000000`, {
          method: "DELETE",
          headers: { apikey: testKey, Authorization: `Bearer ${testKey}`, Prefer: "return=minimal" },
        });
        // 200/204 = delete allowed (even if 0 rows affected), 401/403 = blocked
        if (res.status === 200 || res.status === 204) return { table, status: res.status };
        return null;
      }),
    ),
    // Auth settings
    scanFetch(`${supabaseUrl}/auth/v1/settings`, { headers: { apikey: testKey } })
      .then(async (res) => res.ok ? { settings: await res.json() as Record<string, unknown> } : null)
      .catch(() => null),
    // Storage buckets
    scanFetch(`${supabaseUrl}/storage/v1/bucket`, { headers: { apikey: testKey, Authorization: `Bearer ${testKey}` } })
      .then(async (res) => res.ok ? (await res.json() as { name: string; public: boolean }[]) : null)
      .catch(() => null),
  ]);

  for (const r of writeResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const { table, status } = r.value;
    findings.push({
      id: `supabase-rls-write-${table}`, module: "Supabase", severity: "critical",
      title: `Table "${table}" allows anonymous INSERT`,
      description: `The "${table}" table accepts writes with just the anon key.`,
      evidence: `POST ${supabaseUrl}/rest/v1/${table}\nStatus: ${status}`,
      remediation: `Add RLS INSERT policies to "${table}" to restrict who can write data.`,
      cwe: "CWE-862", owasp: "A01:2021",
      codeSnippet: `-- Enable RLS and add insert policy\nALTER TABLE "${table}" ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "Users can only insert own data"\n  ON "${table}" FOR INSERT\n  WITH CHECK (auth.uid() = user_id);`,
    });
  }

  for (const r of deleteResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const { table, status } = r.value;
    // Only flag if we didn't already find this table in read/write checks
    if (findings.some((f) => f.id.includes(table))) continue;
    findings.push({
      id: `supabase-rls-delete-${table}`, module: "Supabase", severity: "critical",
      title: `Table "${table}" allows anonymous DELETE`,
      description: `The "${table}" table accepts DELETE requests with just the anon key. Anyone can delete data from this table.`,
      evidence: `DELETE ${supabaseUrl}/rest/v1/${table}?id=eq.00000000-...\nStatus: ${status} (delete permitted)`,
      remediation: `Add RLS DELETE policies to "${table}" to restrict who can delete data.`,
      cwe: "CWE-862", owasp: "A01:2021",
      codeSnippet: `-- Restrict deletes to row owners\nALTER TABLE "${table}" ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "Users can only delete own data"\n  ON "${table}" FOR DELETE\n  USING (auth.uid() = user_id);`,
    });
  }

  if (authResult) {
    findings.push({
      id: "supabase-auth-settings-exposed", module: "Supabase", severity: "info",
      title: "Supabase auth settings are readable",
      description: "Auth configuration is publicly readable.",
      evidence: `Enabled providers: ${JSON.stringify(authResult.settings.external || {}).substring(0, 200)}`,
      remediation: "This is expected behavior but review your auth provider configuration.",
    });
  }

  if (storageResult) {
    for (const bucket of storageResult) {
      if (bucket.public) {
        findings.push({
          id: `supabase-storage-public-${bucket.name}`, module: "Supabase", severity: "medium",
          title: `Storage bucket "${bucket.name}" is public`,
          description: `The storage bucket "${bucket.name}" is publicly accessible.`,
          evidence: `Bucket: ${bucket.name}, Public: true`,
          remediation: "Make the bucket private and use signed URLs for access.",
          cwe: "CWE-862",
          codeSnippet: `// Use signed URLs instead of public buckets\nconst { data } = await supabase.storage\n  .from("${bucket.name}")\n  .createSignedUrl("file.pdf", 3600);`,
        });
      }
    }
  }

  // Test Edge Functions for missing auth
  const edgeFunctionPaths = [
    "/functions/v1/hello", "/functions/v1/process", "/functions/v1/webhook",
    "/functions/v1/generate", "/functions/v1/chat", "/functions/v1/ai",
    "/functions/v1/stripe", "/functions/v1/payment", "/functions/v1/send",
    "/functions/v1/notify", "/functions/v1/sync", "/functions/v1/cron",
  ];

  // Also discover edge function names from JS bundles
  const edgeFnMatches = allJs.matchAll(/functions\/v1\/([a-zA-Z0-9_-]+)/g);
  for (const m of edgeFnMatches) {
    const path = `/functions/v1/${m[1]}`;
    if (!edgeFunctionPaths.includes(path)) edgeFunctionPaths.push(path);
  }

  const edgeFnResults = await Promise.allSettled(
    edgeFunctionPaths.map(async (path) => {
      // Test without auth header (just anon key in URL, no Bearer token)
      const url = `${supabaseUrl}${path}`;
      const res = await scanFetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ test: true }),
        timeoutMs: 8000,
      });
      const text = await res.text();
      // 401/403 = properly protected, 404 = doesn't exist
      if (res.status === 401 || res.status === 403 || res.status === 404) return null;
      if (text.length < 5) return null;
      // If function responds successfully without auth, it's exposed
      if (res.ok || res.status === 400) {
        return { path, status: res.status, text: text.substring(0, 300) };
      }
      return null;
    }),
  );

  for (const r of edgeFnResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const { path, status, text } = r.value;
    findings.push({
      id: `supabase-edge-fn-no-auth-${path.replace(/\//g, "-")}`, module: "Supabase", severity: "high",
      title: `Edge Function "${path}" accessible without authentication`,
      description: "This Supabase Edge Function responds to requests without a valid JWT. Anyone can invoke it directly, potentially abusing server-side logic, consuming resources, or accessing internal services.",
      evidence: `POST ${supabaseUrl}${path} (no Authorization header)\nStatus: ${status}\nResponse: ${text}`,
      remediation: "Verify the JWT in your Edge Function. Supabase passes the Authorization header to functions — validate it before processing.",
      cwe: "CWE-306", owasp: "A07:2021",
      codeSnippet: `// supabase/functions/my-function/index.ts\nimport { createClient } from "@supabase/supabase-js";\n\nDeno.serve(async (req) => {\n  const authHeader = req.headers.get("Authorization");\n  if (!authHeader) return new Response("Unauthorized", { status: 401 });\n\n  const supabase = createClient(\n    Deno.env.get("SUPABASE_URL")!,\n    Deno.env.get("SUPABASE_ANON_KEY")!,\n    { global: { headers: { Authorization: authHeader } } }\n  );\n  const { data: { user } } = await supabase.auth.getUser();\n  if (!user) return new Response("Unauthorized", { status: 401 });\n  // ... handle request\n});`,
    });
  }

  // Test UPDATE access on tables — anon should not be able to modify data
  const updateResults = await Promise.allSettled(
    ["users", "profiles", "posts", "orders", "settings"].map(async (table) => {
      const res = await scanFetch(`${supabaseUrl}/rest/v1/${table}?id=eq.00000000-0000-0000-0000-000000000000`, {
        method: "PATCH",
        headers: { apikey: testKey, Authorization: `Bearer ${testKey}`, "Content-Type": "application/json", Prefer: "return=minimal" },
        body: JSON.stringify({ _vibeshield_test: true }),
      });
      if (res.status === 200 || res.status === 204) return { table, status: res.status };
      return null;
    }),
  );

  for (const r of updateResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const { table, status } = r.value;
    if (findings.some((f) => f.id.includes(table))) continue;
    findings.push({
      id: `supabase-rls-update-${table}`, module: "Supabase", severity: "critical",
      title: `Table "${table}" allows anonymous UPDATE`,
      description: `The "${table}" table accepts PATCH/UPDATE requests with just the anon key. Anyone can modify existing data.`,
      evidence: `PATCH ${supabaseUrl}/rest/v1/${table}?id=eq.00000000-...\nStatus: ${status} (update permitted)`,
      remediation: `Add RLS UPDATE policies to "${table}" to restrict who can modify data.`,
      cwe: "CWE-862", owasp: "A01:2021",
      codeSnippet: `-- Restrict updates to row owners\nALTER TABLE "${table}" ENABLE ROW LEVEL SECURITY;\nCREATE POLICY "Users can only update own data"\n  ON "${table}" FOR UPDATE\n  USING (auth.uid() = user_id)\n  WITH CHECK (auth.uid() = user_id);`,
    });
  }

  // Test RPC (database functions) for missing auth
  const rpcNames = [
    "get_user", "get_users", "search_users", "get_profile",
    "get_orders", "process_payment", "send_email", "generate_report",
    "admin_action", "reset_password", "grant_access", "update_role",
    "get_stats", "get_analytics", "export_data", "delete_account",
  ];
  // Also discover RPC function names from JS bundles
  const rpcMatches = allJs.matchAll(/\.rpc\(\s*["']([a-zA-Z_][a-zA-Z0-9_]*)["']/g);
  for (const m of rpcMatches) {
    if (!rpcNames.includes(m[1])) rpcNames.push(m[1]);
  }

  const rpcResults = await Promise.allSettled(
    rpcNames.map(async (fn) => {
      const res = await scanFetch(`${supabaseUrl}/rest/v1/rpc/${fn}`, {
        method: "POST",
        headers: { apikey: testKey, Authorization: `Bearer ${testKey}`, "Content-Type": "application/json" },
        body: "{}",
        timeoutMs: 5000,
      });
      // 404 = doesn't exist, 401/403 = protected, 200/400/422 = exists and accessible
      if (res.status === 404 || res.status === 401 || res.status === 403) return null;
      const text = await res.text();
      if (text.length < 3) return null;
      return { fn, status: res.status, text: text.substring(0, 300) };
    }),
  );

  const accessibleRpcs: string[] = [];
  const dangerousRpcs: string[] = [];
  for (const r of rpcResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const { fn } = r.value;
    accessibleRpcs.push(fn);
    if (/admin|delete|reset|grant|role|payment|export/i.test(fn)) dangerousRpcs.push(fn);
  }

  if (accessibleRpcs.length > 0) {
    findings.push({
      id: "supabase-rpc-no-auth", module: "Supabase",
      severity: dangerousRpcs.length > 0 ? "critical" : "high",
      title: `${accessibleRpcs.length} Supabase RPC function${accessibleRpcs.length > 1 ? "s" : ""} callable with anon key`,
      description: `Found ${accessibleRpcs.length} database functions accessible without user authentication: ${accessibleRpcs.join(", ")}.${dangerousRpcs.length > 0 ? ` ${dangerousRpcs.length} appear privileged: ${dangerousRpcs.join(", ")}.` : ""} These functions can be invoked by anyone with the anon key.`,
      evidence: `Accessible RPC functions:\n${accessibleRpcs.map((fn) => `  rpc/${fn}`).join("\n")}`,
      remediation: "Add SECURITY DEFINER with proper auth checks, or use SECURITY INVOKER and ensure the calling role has appropriate permissions. Always verify auth.uid() inside the function.",
      cwe: "CWE-862", owasp: "A01:2021",
      codeSnippet: `-- Protect RPC functions with auth checks\nCREATE OR REPLACE FUNCTION get_user_data()\nRETURNS json\nLANGUAGE plpgsql\nSECURITY DEFINER\nAS $$\nDECLARE\n  user_id uuid;\nBEGIN\n  user_id := auth.uid();\n  IF user_id IS NULL THEN\n    RAISE EXCEPTION 'Not authenticated';\n  END IF;\n  RETURN (SELECT row_to_json(u) FROM users u WHERE u.id = user_id);\nEND;\n$$;`,
    });
  }

  // Test Realtime channel authorization
  const realtimeChannels = ["public", "private", "admin", "notifications", "chat", "updates"];
  // Also discover channel names from JS
  const channelMatches = allJs.matchAll(/\.channel\(\s*["']([^"']+)["']\)/g);
  for (const m of channelMatches) {
    if (!realtimeChannels.includes(m[1])) realtimeChannels.push(m[1]);
  }

  // Test if realtime endpoint is accessible (WebSocket upgrade via HTTP)
  const realtimeUrl = `${supabaseUrl}/realtime/v1/websocket?apikey=${testKey}&vsn=1.0.0`;
  try {
    const rtRes = await scanFetch(realtimeUrl, { timeoutMs: 5000 });
    // A 101 or 200 response means the realtime endpoint is accessible with just the anon key
    if (rtRes.ok || rtRes.status === 101 || rtRes.status === 426) {
      // Check if Realtime is enabled — try subscribing to postgres_changes on sensitive tables
      const sensitiveChannelResults = await Promise.allSettled(
        ["users", "auth.users", "payments", "orders", "sessions"].map(async (table) => {
          // Use the REST-based realtime health check
          const healthUrl = `${supabaseUrl}/realtime/v1/api/health`;
          const res = await scanFetch(healthUrl, {
            headers: { apikey: testKey },
            timeoutMs: 5000,
          });
          if (res.ok) return { table, accessible: true };
          return null;
        }),
      );

      const realtimeAccessible = sensitiveChannelResults.some(
        (r) => r.status === "fulfilled" && r.value?.accessible,
      );

      if (realtimeAccessible) {
        // Check if any RLS-unprotected tables could leak data via Realtime
        const rlsVulnTables = findings
          .filter((f) => f.id.startsWith("supabase-rls-read-"))
          .map((f) => f.id.replace("supabase-rls-read-", ""));

        if (rlsVulnTables.length > 0) {
          findings.push({
            id: "supabase-realtime-rls-leak", module: "Supabase", severity: "high",
            title: "Realtime subscriptions may leak data from RLS-unprotected tables",
            description: `Supabase Realtime is accessible and the following tables lack RLS policies: ${rlsVulnTables.join(", ")}. Attackers can subscribe to postgres_changes on these tables to receive all INSERT/UPDATE/DELETE events in real-time.`,
            evidence: `Realtime endpoint: ${supabaseUrl}/realtime/v1\nTables without RLS: ${rlsVulnTables.join(", ")}`,
            remediation: "Enable RLS on all tables. Realtime respects RLS policies — once RLS is enabled, only authorized changes are broadcast to subscribers.",
            cwe: "CWE-862", owasp: "A01:2021",
            codeSnippet: `-- Enable RLS to protect Realtime subscriptions\n${rlsVulnTables.map((t) => `ALTER TABLE "${t}" ENABLE ROW LEVEL SECURITY;`).join("\n")}\n\n-- Realtime respects RLS, so add SELECT policies:\n-- CREATE POLICY "Users see own data" ON "table"\n--   FOR SELECT USING (auth.uid() = user_id);`,
          });
        }
      }
    }
  } catch {
    // Realtime not accessible — fine
  }

  return findings;
};
