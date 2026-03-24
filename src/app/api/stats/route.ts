import { NextResponse } from "next/server";
import { getStats } from "@/lib/scanner/store";

export const GET = () => NextResponse.json(getStats());
