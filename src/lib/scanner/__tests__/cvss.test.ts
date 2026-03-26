import { describe, it, expect } from "vitest";
import { getCvssScore, cvssRating } from "../cvss";

describe("cvss", () => {
  describe("getCvssScore", () => {
    it("returns correct score for known CWE (SQL injection)", () => {
      const result = getCvssScore("CWE-89", "critical");
      expect(result).toBeDefined();
      expect(result!.score).toBeGreaterThanOrEqual(9.0);
      expect(result!.vector).toContain("CVSS:3.1/");
      expect(result!.rating).toBe("Critical");
    });

    it("returns correct score for XSS (CWE-79)", () => {
      const result = getCvssScore("CWE-79", "medium");
      expect(result).toBeDefined();
      expect(result!.score).toBeGreaterThanOrEqual(5.0);
      expect(result!.score).toBeLessThan(9.0);
    });

    it("returns correct score for clickjacking (CWE-1021)", () => {
      const result = getCvssScore("CWE-1021", "low");
      expect(result).toBeDefined();
      expect(result!.score).toBeGreaterThan(0);
      expect(result!.score).toBeLessThan(7.0);
    });

    it("falls back to severity-based score when CWE unknown", () => {
      const result = getCvssScore("CWE-99999", "high");
      expect(result).toBeDefined();
      expect(result!.score).toBe(7.5);
      expect(result!.rating).toBe("High");
    });

    it("falls back to severity when no CWE provided", () => {
      const result = getCvssScore(undefined, "critical");
      expect(result).toBeDefined();
      expect(result!.score).toBe(9.5);
    });

    it("returns score for info severity", () => {
      const result = getCvssScore(undefined, "info");
      expect(result).toBeDefined();
      expect(result!.score).toBe(0);
      expect(result!.rating).toBe("None");
    });

    it("handles CWE with different formats", () => {
      // Should handle "CWE-89" format
      const r1 = getCvssScore("CWE-89");
      expect(r1).toBeDefined();
    });
  });

  describe("cvssRating", () => {
    it("returns correct rating for each range", () => {
      expect(cvssRating(0)).toBe("None");
      expect(cvssRating(0.1)).toBe("Low");
      expect(cvssRating(3.9)).toBe("Low");
      expect(cvssRating(4.0)).toBe("Medium");
      expect(cvssRating(6.9)).toBe("Medium");
      expect(cvssRating(7.0)).toBe("High");
      expect(cvssRating(8.9)).toBe("High");
      expect(cvssRating(9.0)).toBe("Critical");
      expect(cvssRating(10.0)).toBe("Critical");
    });
  });
});
