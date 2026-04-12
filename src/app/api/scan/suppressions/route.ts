import { NextResponse, type NextRequest } from "next/server";
import { validateApiKey } from "@/lib/auth";

/**
 * Manage finding suppressions (false positives / accepted risks).
 *
 * GET /api/scan/suppressions — list all suppressions
 * POST /api/scan/suppressions — add a suppression
 * DELETE /api/scan/suppressions — remove a suppression
 */

// In-memory store (will be backed by SQLite when db.ts is wired up)
const globalForSuppressions = globalThis as unknown as {
  __vibeshieldSuppressions?: Map<
    string,
    { reason: string; createdAt: string; createdBy?: string }
  >;
};
if (!globalForSuppressions.__vibeshieldSuppressions) {
  globalForSuppressions.__vibeshieldSuppressions = new Map();
}
const suppressions = globalForSuppressions.__vibeshieldSuppressions;

export async function GET(req: NextRequest) {
  const auth = validateApiKey(req);
  if (!auth.valid)
    return NextResponse.json({ error: auth.error }, { status: 401 });

  const entries = Array.from(suppressions.entries()).map(([key, val]) => ({
    findingKey: key,
    ...val,
  }));

  return NextResponse.json({ suppressions: entries, total: entries.length });
}

export async function POST(req: NextRequest) {
  const auth = validateApiKey(req);
  if (!auth.valid)
    return NextResponse.json({ error: auth.error }, { status: 401 });

  let body: { findingKey?: string; reason?: string };
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON in request body" }, { status: 400 }); }
  const { findingKey, reason } = body as {
    findingKey?: string;
    reason?: string;
  };

  if (!findingKey || typeof findingKey !== "string") {
    return NextResponse.json(
      { error: "findingKey is required (format: 'module::title')" },
      { status: 400 },
    );
  }
  if (!reason || typeof reason !== "string") {
    return NextResponse.json(
      { error: "reason is required" },
      { status: 400 },
    );
  }

  suppressions.set(findingKey, {
    reason,
    createdAt: new Date().toISOString(),
  });

  return NextResponse.json({ ok: true, findingKey, reason });
}

export async function DELETE(req: NextRequest) {
  const auth = validateApiKey(req);
  if (!auth.valid)
    return NextResponse.json({ error: auth.error }, { status: 401 });

  let deleteBody: { findingKey?: string };
  try { deleteBody = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON in request body" }, { status: 400 }); }
  const { findingKey } = deleteBody;

  if (!findingKey) {
    return NextResponse.json(
      { error: "findingKey is required" },
      { status: 400 },
    );
  }

  const existed = suppressions.delete(findingKey);

  return NextResponse.json({ ok: true, deleted: existed });
}

// Export for use in scanner
export const getSuppressions = () => suppressions;
export const isSuppressed = (module: string, title: string): boolean => {
  return suppressions.has(`${module}::${title}`);
};
