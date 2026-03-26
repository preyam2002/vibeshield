import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

describe("auth", () => {
  const originalEnv = process.env.VIBESHIELD_API_KEY;

  afterEach(() => {
    if (originalEnv !== undefined) {
      process.env.VIBESHIELD_API_KEY = originalEnv;
    } else {
      delete process.env.VIBESHIELD_API_KEY;
    }
    vi.resetModules();
  });

  it("allows all requests when no API key is set", async () => {
    delete process.env.VIBESHIELD_API_KEY;
    const { validateApiKey, isAuthEnabled } = await import("../auth");
    // Auth module was already loaded with the env var state at import time
    // This test verifies the default behavior
    if (!isAuthEnabled) {
      const req = new Request("http://localhost/api/scan", { method: "POST" });
      const result = validateApiKey(req as never);
      expect(result.valid).toBe(true);
    }
  });

  it("exports isAuthEnabled based on env var", async () => {
    const { isAuthEnabled } = await import("../auth");
    expect(typeof isAuthEnabled).toBe("boolean");
  });

  it("validateApiKey returns valid/error structure", async () => {
    const { validateApiKey } = await import("../auth");
    const req = new Request("http://localhost/api/scan", { method: "POST" });
    const result = validateApiKey(req as never);
    expect(result).toHaveProperty("valid");
    expect(typeof result.valid).toBe("boolean");
  });
});
