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
      });
    }
  }

  // Test write access, auth settings, and storage in parallel
  const [writeResults, authResult, storageResult] = await Promise.all([
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
        });
      }
    }
  }

  return findings;
};
