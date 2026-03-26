import { describe, it, expect } from "vitest";
import {
  MODULE_TIMEOUT_MS,
  MAX_FINDINGS_PER_MODULE,
  SECURITY_BATCH_SIZE,
  CIRCUIT_BREAKER_THRESHOLD,
  MAX_JS_FILES,
  MAX_CONCURRENT_SCANS,
  RATE_LIMIT_PER_TARGET,
  RATE_LIMIT_PER_IP,
  RATE_LIMIT_WINDOW_MS,
  MAX_STORED_SCANS,
  STALE_SCAN_TIMEOUT_MS,
  DEFAULT_FETCH_TIMEOUT_MS,
} from "../config";

describe("config", () => {
  it("has sensible defaults", () => {
    expect(MODULE_TIMEOUT_MS).toBe(120_000);
    expect(MAX_FINDINGS_PER_MODULE).toBe(8);
    expect(SECURITY_BATCH_SIZE).toBe(21);
    expect(CIRCUIT_BREAKER_THRESHOLD).toBe(4);
    expect(MAX_JS_FILES).toBe(40);
    expect(MAX_CONCURRENT_SCANS).toBe(10);
    expect(RATE_LIMIT_PER_TARGET).toBe(3);
    expect(RATE_LIMIT_PER_IP).toBe(20);
    expect(RATE_LIMIT_WINDOW_MS).toBe(300_000);
    expect(MAX_STORED_SCANS).toBe(100);
    expect(STALE_SCAN_TIMEOUT_MS).toBe(300_000);
    expect(DEFAULT_FETCH_TIMEOUT_MS).toBe(10_000);
  });

  it("all values are positive numbers", () => {
    const values = [
      MODULE_TIMEOUT_MS, MAX_FINDINGS_PER_MODULE, SECURITY_BATCH_SIZE,
      CIRCUIT_BREAKER_THRESHOLD, MAX_JS_FILES, MAX_CONCURRENT_SCANS,
      RATE_LIMIT_PER_TARGET, RATE_LIMIT_PER_IP, RATE_LIMIT_WINDOW_MS,
      MAX_STORED_SCANS, STALE_SCAN_TIMEOUT_MS, DEFAULT_FETCH_TIMEOUT_MS,
    ];
    for (const val of values) {
      expect(val).toBeGreaterThan(0);
      expect(typeof val).toBe("number");
      expect(Number.isFinite(val)).toBe(true);
    }
  });
});
