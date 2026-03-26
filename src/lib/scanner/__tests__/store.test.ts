import { describe, it, expect, beforeEach } from "vitest";
import {
  createScan,
  getScan,
  getActiveScansCount,
  findActiveScan,
  findPreviousScan,
  updateScanStatus,
  addFindings,
  setModules,
  updateModule,
  setTechInfo,
  setSurface,
  cancelScan,
  getStats,
  getRecentScans,
  getScanHistory,
  registerAbort,
} from "../store";
import type { Finding, ModuleStatus } from "../types";

// Reset global state between tests — clear the existing Maps rather than replacing them
// (store.ts holds const references to the original Maps)
beforeEach(() => {
  const g = globalThis as unknown as {
    __vibeshieldScans?: Map<string, unknown>;
    __vibeshieldAbort?: Map<string, unknown>;
  };
  g.__vibeshieldScans?.clear();
  g.__vibeshieldAbort?.clear();
});

describe("store", () => {
  describe("createScan", () => {
    it("creates a scan with correct defaults", () => {
      const scan = createScan("test-1", "https://example.com", "full");
      expect(scan.id).toBe("test-1");
      expect(scan.target).toBe("https://example.com");
      expect(scan.status).toBe("queued");
      expect(scan.mode).toBe("full");
      expect(scan.score).toBe(100);
      expect(scan.grade).toBe("-");
      expect(scan.findings).toEqual([]);
      expect(scan.summary).toEqual({ critical: 0, high: 0, medium: 0, low: 0, info: 0, total: 0 });
    });

    it("stores and retrieves scan by id", () => {
      createScan("test-2", "https://example.com");
      const scan = getScan("test-2");
      expect(scan).toBeDefined();
      expect(scan!.id).toBe("test-2");
    });

    it("returns undefined for non-existent scan", () => {
      expect(getScan("nonexistent")).toBeUndefined();
    });

    it("defaults mode to full", () => {
      const scan = createScan("test-3", "https://example.com");
      expect(scan.mode).toBe("full");
    });
  });

  describe("updateScanStatus", () => {
    it("updates status to scanning", () => {
      createScan("s1", "https://example.com");
      updateScanStatus("s1", "scanning");
      expect(getScan("s1")!.status).toBe("scanning");
    });

    it("sets completedAt on completion", () => {
      createScan("s2", "https://example.com");
      updateScanStatus("s2", "completed");
      expect(getScan("s2")!.completedAt).toBeDefined();
    });

    it("sets error message on failure", () => {
      createScan("s3", "https://example.com");
      updateScanStatus("s3", "failed", "Connection refused");
      const scan = getScan("s3")!;
      expect(scan.status).toBe("failed");
      expect(scan.error).toBe("Connection refused");
    });
  });

  describe("addFindings", () => {
    it("adds findings and recalculates summary", () => {
      createScan("f1", "https://example.com");
      const findings: Finding[] = [
        { id: "1", module: "Headers", severity: "medium", title: "Missing HSTS", description: "No HSTS header", remediation: "Add HSTS" },
        { id: "2", module: "SSL", severity: "high", title: "Weak cipher", description: "Weak cipher suite", remediation: "Upgrade ciphers" },
      ];
      addFindings("f1", findings);
      const scan = getScan("f1")!;
      expect(scan.findings.length).toBe(2);
      expect(scan.summary.medium).toBe(1);
      expect(scan.summary.high).toBe(1);
      expect(scan.summary.total).toBe(2);
      expect(scan.score).toBeLessThan(100);
    });

    it("deduplicates findings by module::title", () => {
      createScan("f2", "https://example.com");
      const finding: Finding = { id: "1", module: "Headers", severity: "medium", title: "Missing HSTS", description: "desc", remediation: "fix" };
      addFindings("f2", [finding]);
      addFindings("f2", [{ ...finding, id: "2" }]); // Same module::title, different id
      expect(getScan("f2")!.findings.length).toBe(1);
    });

    it("allows same title from different modules", () => {
      createScan("f3", "https://example.com");
      addFindings("f3", [{ id: "1", module: "headers", severity: "high", title: "Issue", description: "d", remediation: "r" }]);
      addFindings("f3", [{ id: "2", module: "ssl", severity: "high", title: "Issue", description: "d", remediation: "r" }]);
      expect(getScan("f3")!.findings).toHaveLength(2);
    });
  });

  describe("score calculation", () => {
    it("critical findings heavily penalize score", () => {
      createScan("sc1", "https://example.com");
      addFindings("sc1", [
        { id: "1", module: "Injection", severity: "critical", title: "SQLi", description: "SQL injection", remediation: "Use parameterized queries", confidence: 90 },
      ]);
      expect(getScan("sc1")!.score).toBeLessThan(75);
    });

    it("info findings don't affect score", () => {
      createScan("sc2", "https://example.com");
      addFindings("sc2", [
        { id: "1", module: "Recon", severity: "info", title: "Tech detected", description: "Uses React", remediation: "N/A" },
      ]);
      expect(getScan("sc2")!.score).toBe(100);
    });

    it("assigns correct grades based on score", () => {
      createScan("g1", "https://example.com");
      expect(getScan("g1")!.grade).toBe("-"); // No findings yet

      // Add enough critical findings to drop grade to F
      const criticals: Finding[] = Array.from({ length: 5 }, (_, i) => ({
        id: `c${i}`, module: "Test", severity: "critical" as const, title: `Critical ${i}`,
        description: "desc", remediation: "fix", confidence: 95,
      }));
      addFindings("g1", criticals);
      const scan = getScan("g1")!;
      expect(scan.score).toBeLessThan(50);
      expect(["D", "D+", "F"]).toContain(scan.grade);
    });
  });

  describe("active scans", () => {
    it("counts active scans", () => {
      createScan("a1", "https://a.com");
      createScan("a2", "https://b.com");
      updateScanStatus("a1", "scanning");
      expect(getActiveScansCount()).toBe(2); // a1 scanning, a2 queued
    });

    it("finds active scan by target", () => {
      createScan("a3", "https://target.com");
      updateScanStatus("a3", "scanning");
      expect(findActiveScan("https://target.com")).toBeDefined();
      expect(findActiveScan("https://other.com")).toBeUndefined();
    });
  });

  describe("comparison", () => {
    it("builds comparison when previous scan exists", () => {
      createScan("prev", "https://example.com");
      addFindings("prev", [
        { id: "1", module: "Headers", severity: "medium", title: "Missing HSTS", description: "d", remediation: "r" },
        { id: "2", module: "SSL", severity: "high", title: "Weak cipher", description: "d", remediation: "r" },
      ]);
      updateScanStatus("prev", "completed");

      createScan("curr", "https://example.com");
      addFindings("curr", [
        { id: "3", module: "Headers", severity: "medium", title: "Missing HSTS", description: "d", remediation: "r" },
        { id: "4", module: "CORS", severity: "high", title: "Wildcard origin", description: "d", remediation: "r" },
      ]);
      updateScanStatus("curr", "completed");

      const scan = getScan("curr")!;
      expect(scan.comparison).toBeDefined();
      expect(scan.comparison!.previousId).toBe("prev");
      expect(scan.comparison!.fixedFindings).toHaveLength(1); // "Weak cipher" fixed
      expect(scan.comparison!.newFindings).toHaveLength(1); // "Wildcard origin" new
    });
  });

  describe("modules", () => {
    it("sets and updates modules", () => {
      createScan("m1", "https://example.com");
      setModules("m1", [
        { name: "Headers", status: "pending", findingsCount: 0 },
        { name: "SSL", status: "pending", findingsCount: 0 },
      ]);
      updateModule("m1", "Headers", { status: "running" });
      expect(getScan("m1")!.modules[0].status).toBe("running");

      updateModule("m1", "Headers", { status: "completed", findingsCount: 3, durationMs: 500 });
      const mod = getScan("m1")!.modules[0];
      expect(mod.status).toBe("completed");
      expect(mod.findingsCount).toBe(3);
      expect(mod.durationMs).toBe(500);
    });
  });

  describe("cancelScan", () => {
    it("cancels a running scan", () => {
      createScan("c1", "https://example.com");
      updateScanStatus("c1", "scanning");
      setModules("c1", [
        { name: "Headers", status: "pending", findingsCount: 0 },
      ]);
      const controller = new AbortController();
      registerAbort("c1", controller);

      const result = cancelScan("c1");
      expect(result).toBe(true);
      expect(getScan("c1")!.status).toBe("failed");
      expect(getScan("c1")!.error).toContain("cancelled");
      expect(controller.signal.aborted).toBe(true);
    });

    it("returns false for non-running scan", () => {
      createScan("c2", "https://example.com");
      updateScanStatus("c2", "completed");
      expect(cancelScan("c2")).toBe(false);
    });

    it("marks pending modules as skipped", () => {
      createScan("c3", "https://example.com");
      updateScanStatus("c3", "scanning");
      setModules("c3", [
        { name: "a", status: "completed", findingsCount: 0 },
        { name: "b", status: "pending", findingsCount: 0 },
        { name: "c", status: "running", findingsCount: 0 },
      ]);
      cancelScan("c3");
      const mods = getScan("c3")!.modules;
      expect(mods.find(m => m.name === "a")!.status).toBe("completed");
      expect(mods.find(m => m.name === "b")!.status).toBe("skipped");
      expect(mods.find(m => m.name === "c")!.status).toBe("skipped");
    });
  });

  describe("getRecentScans", () => {
    it("returns scans sorted with active first", () => {
      createScan("r1", "https://a.com");
      updateScanStatus("r1", "completed");
      createScan("r2", "https://b.com");
      updateScanStatus("r2", "scanning");

      const recent = getRecentScans();
      expect(recent[0].id).toBe("r2"); // Active scan first
    });
  });

  describe("getStats", () => {
    it("computes aggregate statistics", () => {
      createScan("st1", "https://a.com");
      addFindings("st1", [
        { id: "1", module: "Headers", severity: "high", title: "t1", description: "d", remediation: "r" },
      ]);
      updateScanStatus("st1", "completed");

      createScan("st2", "https://b.com");
      addFindings("st2", [
        { id: "2", module: "Headers", severity: "medium", title: "t2", description: "d", remediation: "r" },
        { id: "3", module: "SSL", severity: "low", title: "t3", description: "d", remediation: "r" },
      ]);
      updateScanStatus("st2", "completed");

      const stats = getStats();
      expect(stats.completedScans).toBe(2);
      expect(stats.totalFindings).toBe(3);
      expect(stats.uniqueTargets).toBe(2);
      expect(stats.topModules.length).toBe(2);
    });
  });

  describe("getScanHistory", () => {
    it("returns completed scan history for a target", () => {
      createScan("s1", "https://example.com");
      updateScanStatus("s1", "completed");
      createScan("s2", "https://example.com");
      updateScanStatus("s2", "completed");
      createScan("s3", "https://other.com");
      updateScanStatus("s3", "completed");

      const history = getScanHistory("https://example.com");
      expect(history).toHaveLength(2);
      expect(history.every(h => h.id !== "s3")).toBe(true);
    });
  });

  describe("tech info and surface", () => {
    it("sets technology info", () => {
      createScan("t1", "https://example.com");
      setTechInfo("t1", ["React", "Next.js"], true);
      const scan = getScan("t1")!;
      expect(scan.technologies).toEqual(["React", "Next.js"]);
      expect(scan.isSpa).toBe(true);
    });

    it("sets attack surface", () => {
      createScan("t2", "https://example.com");
      setSurface("t2", { pages: 5, apiEndpoints: 3, jsFiles: 10, forms: 2, cookies: 4 });
      expect(getScan("t2")!.surface).toEqual({ pages: 5, apiEndpoints: 3, jsFiles: 10, forms: 2, cookies: 4 });
    });
  });
});
