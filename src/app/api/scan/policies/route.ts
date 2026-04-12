import { NextResponse, type NextRequest } from "next/server";
import { validateApiKey } from "@/lib/auth";

/**
 * Manage scan policies — reusable configurations that define which modules run.
 *
 * GET /api/scan/policies — list all policies
 * POST /api/scan/policies — create a policy
 * DELETE /api/scan/policies — delete a policy
 */

interface ScanPolicy {
  id: string;
  name: string;
  description: string;
  enabledModules: string[];
  createdAt: string;
}

const globalForPolicies = globalThis as unknown as {
  __vibeshieldPolicies?: Map<string, ScanPolicy>;
};
if (!globalForPolicies.__vibeshieldPolicies) {
  globalForPolicies.__vibeshieldPolicies = new Map();
}
const policies = globalForPolicies.__vibeshieldPolicies;

export async function GET(req: NextRequest) {
  const auth = validateApiKey(req);
  if (!auth.valid)
    return NextResponse.json({ error: auth.error }, { status: 401 });

  const entries = Array.from(policies.values());

  return NextResponse.json({ policies: entries, total: entries.length });
}

export async function POST(req: NextRequest) {
  const auth = validateApiKey(req);
  if (!auth.valid)
    return NextResponse.json({ error: auth.error }, { status: 401 });

  let body: { name?: string; description?: string; enabledModules?: string[] };
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON in request body" }, { status: 400 }); }
  const { name, description, enabledModules } = body as {
    name?: string;
    description?: string;
    enabledModules?: string[];
  };

  if (!name || typeof name !== "string") {
    return NextResponse.json(
      { error: "name is required" },
      { status: 400 },
    );
  }
  if (!Array.isArray(enabledModules) || enabledModules.length === 0) {
    return NextResponse.json(
      { error: "enabledModules must be a non-empty string array" },
      { status: 400 },
    );
  }

  const id = crypto.randomUUID();
  const policy: ScanPolicy = {
    id,
    name,
    description: description ?? "",
    enabledModules,
    createdAt: new Date().toISOString(),
  };

  policies.set(id, policy);

  return NextResponse.json({ ok: true, policy });
}

export async function DELETE(req: NextRequest) {
  const auth = validateApiKey(req);
  if (!auth.valid)
    return NextResponse.json({ error: auth.error }, { status: 401 });

  let deleteBody: { id?: string };
  try { deleteBody = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON in request body" }, { status: 400 }); }
  const { id } = deleteBody;

  if (!id) {
    return NextResponse.json(
      { error: "id is required" },
      { status: 400 },
    );
  }

  const existed = policies.delete(id);

  return NextResponse.json({ ok: true, deleted: existed });
}
