import { NextResponse } from "next/server";
import { SECURITY_MODULES, STRESS_MODULES } from "@/lib/scanner";

export async function GET() {
  const toInfo = (m: { name: string; description: string; category: string }) => ({
    name: m.name,
    description: m.description,
    category: m.category,
  });

  return NextResponse.json({
    security: SECURITY_MODULES.map(toInfo),
    stress: STRESS_MODULES.map(toInfo),
  });
}
