import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { clearScanCache, setScanAuth, clearScanAuth } from "../fetch";

describe("fetch", () => {
  beforeEach(() => {
    clearScanCache();
    clearScanAuth();
  });

  afterEach(() => {
    clearScanAuth();
  });

  it("exports clearScanCache", () => {
    expect(typeof clearScanCache).toBe("function");
    clearScanCache(); // Should not throw
  });

  it("exports setScanAuth and clearScanAuth", () => {
    expect(typeof setScanAuth).toBe("function");
    expect(typeof clearScanAuth).toBe("function");

    // Should not throw
    setScanAuth({ headers: { Authorization: "Bearer test" }, cookies: "session=abc" });
    clearScanAuth();
  });

  it("setScanAuth accepts undefined", () => {
    setScanAuth(undefined);
    // Should not throw
  });

  it("setScanAuth accepts partial config", () => {
    setScanAuth({ headers: { "X-Custom": "value" } });
    clearScanAuth();
    setScanAuth({ cookies: "token=xyz" });
    clearScanAuth();
  });
});
