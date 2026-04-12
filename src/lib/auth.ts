import { type NextRequest, NextResponse } from "next/server";

/**
 * Optional API key authentication for programmatic endpoints.
 *
 * Set VIBESHIELD_API_KEY env var to require auth. When unset, all endpoints are open.
 * Multiple keys can be comma-separated: "key1,key2,key3"
 *
 * Clients send: Authorization: Bearer <key> or X-API-Key: <key>
 */

const API_KEYS = (process.env.VIBESHIELD_API_KEY || "")
  .split(",")
  .map((k) => k.trim())
  .filter(Boolean);

export const isAuthEnabled = API_KEYS.length > 0;

export const validateApiKey = (req: NextRequest): { valid: boolean; error?: string } => {
  if (!isAuthEnabled) return { valid: true };

  const authHeader = req.headers.get("authorization");
  const apiKeyHeader = req.headers.get("x-api-key");

  let key: string | null = null;

  if (authHeader?.startsWith("Bearer ")) {
    key = authHeader.slice(7).trim();
  } else if (apiKeyHeader) {
    key = apiKeyHeader.trim();
  }

  if (!key) {
    return { valid: false, error: "Missing API key. Use Authorization: Bearer <key> or X-API-Key: <key>" };
  }

  // Constant-time comparison to prevent timing attacks
  if (!API_KEYS.some((valid) => timingSafeEqual(key!, valid))) {
    return { valid: false, error: "Invalid API key" };
  }

  return { valid: true };
};

export const withAuth = (handler: (req: NextRequest) => Promise<NextResponse>) => {
  return async (req: NextRequest) => {
    const { valid, error } = validateApiKey(req);
    if (!valid) {
      return NextResponse.json({ error }, { status: 401 });
    }
    return handler(req);
  };
};

/** Constant-time string comparison — uses SHA-256 to normalize length before comparing */
const timingSafeEqual = (a: string, b: string): boolean => {
  const { createHash, timingSafeEqual: tsEqual } = require("crypto");
  const hashA = createHash("sha256").update(a).digest();
  const hashB = createHash("sha256").update(b).digest();
  return tsEqual(hashA, hashB);
};
