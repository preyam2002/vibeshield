import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

// Time-based payloads — these cause a measurable delay if command injection exists
const TIME_PAYLOADS = [
  { payload: ";sleep 2", os: "unix" },
  { payload: "|sleep 2", os: "unix" },
  { payload: "`sleep 2`", os: "unix" },
  { payload: "$(sleep 2)", os: "unix" },
  { payload: "& ping -c 2 127.0.0.1 &", os: "unix" },
  { payload: "| timeout /t 2", os: "windows" },
  { payload: "& timeout /t 2 &", os: "windows" },
];

// Output-based payloads — these produce identifiable output
const OUTPUT_PAYLOADS = [
  { payload: ";id", pattern: /uid=\d+\(\w+\)\s+gid=\d+/ },
  { payload: "|id", pattern: /uid=\d+\(\w+\)\s+gid=\d+/ },
  { payload: "$(id)", pattern: /uid=\d+\(\w+\)\s+gid=\d+/ },
  { payload: "`id`", pattern: /uid=\d+\(\w+\)\s+gid=\d+/ },
  { payload: ";cat /etc/hostname", pattern: /^[a-zA-Z0-9._-]+$/m },
  { payload: ";echo vibeshield_cmdi_test", pattern: /vibeshield_cmdi_test/ },
  { payload: "|echo vibeshield_cmdi_test", pattern: /vibeshield_cmdi_test/ },
  { payload: "$(echo vibeshield_cmdi_test)", pattern: /vibeshield_cmdi_test/ },
  // Filter evasion variants
  { payload: ";echo${IFS}vibeshield_cmdi_test", pattern: /vibeshield_cmdi_test/ }, // IFS separator
  { payload: ";e'c'h'o' vibeshield_cmdi_test", pattern: /vibeshield_cmdi_test/ }, // Quote splitting
  { payload: ";ech\"\"o vibeshield_cmdi_test", pattern: /vibeshield_cmdi_test/ }, // Empty quote insertion
  { payload: ";/bin/echo vibeshield_cmdi_test", pattern: /vibeshield_cmdi_test/ }, // Full path
  { payload: ";{echo,vibeshield_cmdi_test}", pattern: /vibeshield_cmdi_test/ }, // Brace expansion
];

export const commandInjectionModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  let count = 0;

  // Collect testable endpoints — focus on params that might be passed to system commands
  const testTargets: { url: string; method: string; paramName: string }[] = [];

  for (const endpoint of target.apiEndpoints) {
    try {
      const url = new URL(endpoint);
      for (const [key] of url.searchParams) {
        testTargets.push({ url: endpoint, method: "GET", paramName: key });
      }
    } catch { /* skip */ }
  }

  // Also probe API endpoints with params commonly passed to system commands
  for (const endpoint of target.apiEndpoints.slice(0, 5)) {
    for (const param of ["cmd", "command", "exec", "host", "hostname", "ip", "ping", "url", "domain", "filename", "dir"]) {
      testTargets.push({ url: endpoint, method: "GET", paramName: param });
    }
  }

  // From forms
  for (const form of target.forms) {
    for (const input of form.inputs) {
      if (input.type === "hidden" || input.type === "submit" || !input.name) continue;
      testTargets.push({
        url: form.action.startsWith("http") ? form.action : target.baseUrl + form.action,
        method: form.method,
        paramName: input.name,
      });
    }
  }

  // Deduplicate
  const seen = new Set<string>();
  const deduped = testTargets.filter((t) => {
    try {
      const key = `${new URL(t.url).pathname}:${t.paramName}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    } catch { return false; }
  });

  const flagged = new Set<string>();

  // Phase 1 & 2 run in parallel across endpoints — time-based payloads are sequential per endpoint
  const allResults = await Promise.allSettled(
    deduped.slice(0, 10).map(async (t) => {
      const pathname = new URL(t.url).pathname;
      const key = `${pathname}:${t.paramName}`;
      if (flagged.has(key)) return null;

      // Phase 1: Time-based detection (sequential per endpoint for baseline accuracy)
      const baseTimes: number[] = [];
      for (let i = 0; i < 3; i++) {
        const start = Date.now();
        try {
          const url = new URL(t.url);
          url.searchParams.set(t.paramName, "normal_value");
          await scanFetch(url.href, { timeoutMs: 8000 });
        } catch { /* skip */ }
        baseTimes.push(Date.now() - start);
      }
      const sortedBase = [...baseTimes].sort((a, b) => a - b);
      const baseline = sortedBase[1] || 500;

      for (const { payload, os } of TIME_PAYLOADS.slice(0, 4)) {
        if (flagged.has(key)) break;
        try {
          const start = Date.now();
          if (t.method === "GET") {
            const url = new URL(t.url);
            url.searchParams.set(t.paramName, `test${payload}`);
            await scanFetch(url.href, { timeoutMs: 8000 });
          } else {
            await scanFetch(t.url, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: `${t.paramName}=${encodeURIComponent(`test${payload}`)}`, timeoutMs: 8000 });
          }
          const elapsed = Date.now() - start;
          if (elapsed >= 1800 && elapsed >= baseline * 2) {
            const confirmStart = Date.now();
            const confirmPayload = payload.replace("2", "1");
            const confirmUrl = new URL(t.url);
            confirmUrl.searchParams.set(t.paramName, `test${confirmPayload}`);
            try { await scanFetch(confirmUrl.href, { timeoutMs: 8000 }); } catch { /* skip */ }
            const confirmElapsed = Date.now() - confirmStart;
            if (confirmElapsed < elapsed * 0.85) {
              flagged.add(key);
              return { type: "time" as const, pathname, paramName: t.paramName, os, payload, elapsed, baseline, confirmElapsed };
            }
          }
        } catch { /* skip */ }
      }

      // Phase 2: Output-based detection (payloads in parallel)
      if (flagged.has(key)) return null;
      let baselineText = "";
      try {
        const url = new URL(t.url);
        url.searchParams.set(t.paramName, "normal_value_12345");
        const res = await scanFetch(url.href, { timeoutMs: 5000 });
        baselineText = await res.text();
      } catch { return null; }

      const outputResults = await Promise.allSettled(
        OUTPUT_PAYLOADS.slice(0, 4)
          .filter(({ pattern }) => !pattern.test(baselineText))
          .map(async ({ payload, pattern }) => {
            let res: Response;
            if (t.method === "GET") {
              const url = new URL(t.url);
              url.searchParams.set(t.paramName, `test${payload}`);
              res = await scanFetch(url.href, { timeoutMs: 5000 });
            } else {
              res = await scanFetch(t.url, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: `${t.paramName}=${encodeURIComponent(`test${payload}`)}`, timeoutMs: 5000 });
            }
            return { payload, pattern, text: await res.text() };
          }),
      );

      for (const r of outputResults) {
        if (r.status !== "fulfilled" || flagged.has(key)) continue;
        const { payload, pattern, text } = r.value;
        if (pattern.test(text) && !pattern.test(baselineText)) {
          flagged.add(key);
          return { type: "output" as const, pathname, paramName: t.paramName, payload, pattern: pattern.source, text: text.substring(0, 300) };
        }
      }
      return null;
    }),
  );

  for (const r of allResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (v.type === "time") {
      findings.push({
        id: `cmdi-time-${count++}`, module: "Command Injection", severity: "critical",
        title: `Command injection (time-based) on ${v.pathname} (param: ${v.paramName})`,
        description: `A ${v.os} sleep command caused a ${v.elapsed}ms delay (baseline: ${v.baseline}ms, confirmation: ${v.confirmElapsed}ms). The server is executing system commands with user input.`,
        evidence: `Payload: test${v.payload}\nResponse time: ${v.elapsed}ms\nBaseline: ${v.baseline}ms\nConfirmation (1s sleep): ${v.confirmElapsed}ms`,
        remediation: "Never pass user input to system commands (exec, spawn, system, popen). Use language-native libraries instead of shelling out. If unavoidable, use allowlists and strict input validation.",
        cwe: "CWE-78", owasp: "A03:2021",
        codeSnippet: `// Instead of exec/spawn with user input:\n// BAD: exec(\`ping \${userInput}\`)\n\n// Use execFile with an args array (no shell interpolation)\nimport { execFile } from "child_process";\nexecFile("ping", ["-c", "1", sanitized], callback);\n\n// Or validate against an allowlist\nconst ALLOWED = new Set(["host-a", "host-b"]);\nif (!ALLOWED.has(input)) throw new Error("Invalid host");`,
      });
    } else {
      findings.push({
        id: `cmdi-output-${count++}`, module: "Command Injection", severity: "critical",
        title: `Command injection on ${v.pathname} (param: ${v.paramName})`,
        description: "A system command payload produced identifiable output in the response. The server is executing user-controlled commands.",
        evidence: `Payload: test${v.payload}\nPattern matched: ${v.pattern}\nResponse excerpt: ${v.text}`,
        remediation: "Never pass user input to system commands. Use language-native libraries instead of shelling out. If unavoidable, use strict allowlists.",
        cwe: "CWE-78", owasp: "A03:2021",
        codeSnippet: `// BAD: passes user input through a shell\n// exec("ls " + userDir)\n\n// GOOD: use execFileSync — no shell, args as array\nimport { execFileSync } from "child_process";\nexecFileSync("ls", [sanitizedDir]);\n\n// Sanitize input: strip shell metacharacters\nconst sanitized = input.replace(/[;&|$\\\`(){}]/g, "");`,
      });
    }
  }

  return findings;
};
