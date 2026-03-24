import { NextResponse } from "next/server";
import { getRecentScans } from "@/lib/scanner/store";

export const GET = () => {
  return NextResponse.json(getRecentScans());
};
