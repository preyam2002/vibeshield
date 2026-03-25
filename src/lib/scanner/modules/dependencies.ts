import type { ScanModule, Finding } from "../types";

// Known vulnerable library versions that can be detected in JS bundles
// Each entry: regex to extract version, vulnerable ranges, CVE/description
const VULNERABLE_LIBS: {
  name: string;
  detect: RegExp;
  versionExtract: RegExp;
  vulnerableBelow: string;
  severity: Finding["severity"];
  cve: string;
  description: string;
}[] = [
  {
    name: "jQuery",
    detect: /jquery[./]|jQuery\s*v?([\d.]+)/,
    versionExtract: /jquery[./\s]*v?(\d+\.\d+\.\d+)/i,
    vulnerableBelow: "3.5.0",
    severity: "medium",
    cve: "CVE-2020-11022",
    description: "jQuery < 3.5.0 is vulnerable to XSS via htmlPrefilter. Untrusted HTML passed to jQuery manipulation methods can execute scripts.",
  },
  {
    name: "Lodash",
    detect: /lodash[./]|lodash\.js/,
    versionExtract: /lodash[./\s]*v?(\d+\.\d+\.\d+)/i,
    vulnerableBelow: "4.17.21",
    severity: "high",
    cve: "CVE-2021-23337",
    description: "Lodash < 4.17.21 is vulnerable to prototype pollution and command injection via template().",
  },
  {
    name: "Angular",
    detect: /angular[./].*?([\d.]+)|AngularJS\s*v?([\d.]+)/,
    versionExtract: /angular(?:js)?[./\s]*v?(1\.\d+\.\d+)/i,
    vulnerableBelow: "1.8.0",
    severity: "high",
    cve: "CVE-2022-25869",
    description: "AngularJS < 1.8.0 has multiple XSS vulnerabilities in template compilation and sanitization.",
  },
  {
    name: "React",
    detect: /react[.-]dom[./]|"react-dom"|react\.production\.min/,
    versionExtract: /react(?:-dom)?[\s./@]*v?(1[0-9]\.\d+\.\d+)/i,
    vulnerableBelow: "16.13.0",
    severity: "medium",
    cve: "CVE-2020-7919",
    description: "React < 16.13.0 can be exploited via XSS in certain server-side rendering configurations.",
  },
  {
    name: "Moment.js",
    detect: /moment[./]|moment\.js|momentjs/,
    versionExtract: /moment[./\s]*v?(\d+\.\d+\.\d+)/i,
    vulnerableBelow: "2.29.4",
    severity: "medium",
    cve: "CVE-2022-31129",
    description: "Moment.js < 2.29.4 is vulnerable to ReDoS via crafted date strings.",
  },
  {
    name: "Axios",
    detect: /axios[./]|axios\.js/,
    versionExtract: /axios[./\s]*v?(\d+\.\d+\.\d+)/i,
    vulnerableBelow: "1.6.0",
    severity: "medium",
    cve: "CVE-2023-45857",
    description: "Axios < 1.6.0 inadvertently leaks XSRF-TOKEN cookie values in cross-site requests.",
  },
  {
    name: "DOMPurify",
    detect: /dompurify[./]|DOMPurify/,
    versionExtract: /dompurify[./\s]*v?(\d+\.\d+\.\d+)/i,
    vulnerableBelow: "3.0.6",
    severity: "high",
    cve: "CVE-2023-49146",
    description: "DOMPurify < 3.0.6 has a mutation XSS bypass allowing script execution via nested form elements.",
  },
  {
    name: "Next.js",
    detect: /next[./]|__NEXT_DATA__|_next\/static/,
    versionExtract: /next[./\s]*v?(1[234]\.\d+\.\d+)/i,
    vulnerableBelow: "14.1.1",
    severity: "high",
    cve: "CVE-2024-34351",
    description: "Next.js < 14.1.1 is vulnerable to SSRF via Server Actions. Attackers can make the server fetch arbitrary URLs.",
  },
  {
    name: "Bootstrap",
    detect: /bootstrap[./]|Bootstrap\s*v/,
    versionExtract: /bootstrap[./\s]*v?([345]\.\d+\.\d+)/i,
    vulnerableBelow: "5.2.0",
    severity: "medium",
    cve: "CVE-2024-6484",
    description: "Bootstrap < 5.2.0 is vulnerable to XSS via carousel and tooltip components with crafted attributes.",
  },
  {
    name: "Handlebars",
    detect: /handlebars[./]|Handlebars\.compile/,
    versionExtract: /handlebars[./\s]*v?(\d+\.\d+\.\d+)/i,
    vulnerableBelow: "4.7.7",
    severity: "high",
    cve: "CVE-2021-23369",
    description: "Handlebars < 4.7.7 is vulnerable to prototype pollution and RCE via crafted templates.",
  },
  {
    name: "Underscore",
    detect: /underscore[./]|_\.VERSION/,
    versionExtract: /underscore[./\s]*v?(\d+\.\d+\.\d+)/i,
    vulnerableBelow: "1.13.6",
    severity: "medium",
    cve: "CVE-2021-23358",
    description: "Underscore < 1.13.6 is vulnerable to arbitrary code injection via the template function.",
  },
  {
    name: "Marked",
    detect: /marked[./]|marked\.parse/,
    versionExtract: /marked[./\s]*v?(\d+\.\d+\.\d+)/i,
    vulnerableBelow: "4.0.10",
    severity: "high",
    cve: "CVE-2022-21681",
    description: "Marked < 4.0.10 is vulnerable to ReDoS and XSS via crafted markdown input.",
  },
  {
    name: "highlight.js",
    detect: /highlight[./]|hljs\.highlight/,
    versionExtract: /highlight\.?js[./\s]*v?(\d+\.\d+\.\d+)/i,
    vulnerableBelow: "10.4.1",
    severity: "medium",
    cve: "CVE-2020-26237",
    description: "highlight.js < 10.4.1 is vulnerable to prototype pollution via crafted language definitions.",
  },
  {
    name: "serialize-javascript",
    detect: /serialize-javascript|serialize\(/,
    versionExtract: /serialize-javascript[./\s]*v?(\d+\.\d+\.\d+)/i,
    vulnerableBelow: "3.1.0",
    severity: "high",
    cve: "CVE-2020-7660",
    description: "serialize-javascript < 3.1.0 is vulnerable to RCE via crafted regex in serialized output.",
  },
  {
    name: "Elliptic",
    detect: /elliptic[./]/,
    versionExtract: /elliptic[./\s]*v?(\d+\.\d+\.\d+)/i,
    vulnerableBelow: "6.5.6",
    severity: "high",
    cve: "CVE-2024-48949",
    description: "Elliptic < 6.5.6 has a signature malleability vulnerability allowing signature forgery in ECDSA.",
  },
  {
    name: "ua-parser-js",
    detect: /ua-parser[.-]js|UAParser/,
    versionExtract: /ua-parser[.-]?js[./\s]*v?(\d+\.\d+\.\d+)/i,
    vulnerableBelow: "0.7.33",
    severity: "medium",
    cve: "CVE-2022-25927",
    description: "ua-parser-js < 0.7.33 is vulnerable to ReDoS via crafted user-agent strings.",
  },
  {
    name: "json5",
    detect: /json5[./]/,
    versionExtract: /json5[./\s]*v?(\d+\.\d+\.\d+)/i,
    vulnerableBelow: "2.2.2",
    severity: "high",
    cve: "CVE-2022-46175",
    description: "json5 < 2.2.2 is vulnerable to prototype pollution via __proto__ keys in parsed JSON5 input.",
  },
  {
    name: "socket.io-client",
    detect: /socket\.io[./]|io\.connect/,
    versionExtract: /socket\.io[.-]?client[./\s]*v?(\d+\.\d+\.\d+)/i,
    vulnerableBelow: "4.6.2",
    severity: "medium",
    cve: "CVE-2024-38355",
    description: "socket.io < 4.6.2 is vulnerable to resource exhaustion via crafted packets, enabling denial-of-service.",
  },
  {
    name: "postcss",
    detect: /postcss[./]/,
    versionExtract: /postcss[./\s]*v?(\d+\.\d+\.\d+)/i,
    vulnerableBelow: "8.4.31",
    severity: "medium",
    cve: "CVE-2023-44270",
    description: "PostCSS < 8.4.31 is vulnerable to line return parsing that can be used to inject malicious CSS.",
  },
  {
    name: "express",
    detect: /express[./]|"express"/,
    versionExtract: /express[./\s]*v?(\d+\.\d+\.\d+)/i,
    vulnerableBelow: "4.19.2",
    severity: "medium",
    cve: "CVE-2024-29041",
    description: "Express < 4.19.2 is vulnerable to open redirect via crafted URL in res.redirect().",
  },
  {
    name: "webpack-dev-server",
    detect: /webpack-dev-server|__webpack_dev_server_client__/,
    versionExtract: /webpack-dev-server[./\s]*v?(\d+\.\d+\.\d+)/i,
    vulnerableBelow: "4.0.0",
    severity: "high",
    cve: "CVE-2018-14732",
    description: "webpack-dev-server < 4.0.0 has no origin check on WebSocket, enabling DNS rebinding attacks.",
  },
  {
    name: "jsonwebtoken",
    detect: /jsonwebtoken[./]|jwt\.sign|jwt\.verify/,
    versionExtract: /jsonwebtoken[./\s]*v?(\d+\.\d+\.\d+)/i,
    vulnerableBelow: "9.0.0",
    severity: "high",
    cve: "CVE-2022-23529",
    description: "jsonwebtoken < 9.0.0 allows attackers to bypass verification by providing a malicious secretOrPublicKey object with a toString() method.",
  },
  {
    name: "semver",
    detect: /semver[./]|semver\.valid/,
    versionExtract: /semver[./\s]*v?(\d+\.\d+\.\d+)/i,
    vulnerableBelow: "7.5.2",
    severity: "medium",
    cve: "CVE-2022-25883",
    description: "semver < 7.5.2 is vulnerable to ReDoS via crafted version strings with long prerelease chains.",
  },
  {
    name: "tough-cookie",
    detect: /tough-cookie[./]|CookieJar/,
    versionExtract: /tough-cookie[./\s]*v?(\d+\.\d+\.\d+)/i,
    vulnerableBelow: "4.1.3",
    severity: "medium",
    cve: "CVE-2023-26136",
    description: "tough-cookie < 4.1.3 is vulnerable to prototype pollution via cookie parsing.",
  },
  {
    name: "Vite",
    detect: /vite[./]|__vite_ssr_|\/@vite/,
    versionExtract: /vite[./\s]*v?([2-6]\.\d+\.\d+)/i,
    vulnerableBelow: "5.1.5",
    severity: "high",
    cve: "CVE-2024-23331",
    description: "Vite < 5.1.5 leaks server options via fs.deny bypass, allowing directory traversal to read arbitrary files.",
  },
  {
    name: "sanitize-html",
    detect: /sanitize-html|sanitizeHtml/,
    versionExtract: /sanitize-html[./\s]*v?(\d+\.\d+\.\d+)/i,
    vulnerableBelow: "2.12.1",
    severity: "high",
    cve: "CVE-2024-21501",
    description: "sanitize-html < 2.12.1 has an XSS bypass via recursive nesting of allowlisted HTML tags.",
  },
  {
    name: "chart.js",
    detect: /chart\.js|Chart\.register/,
    versionExtract: /chart\.?js[./\s]*v?([234]\.\d+\.\d+)/i,
    vulnerableBelow: "4.4.2",
    severity: "medium",
    cve: "CVE-2024-25104",
    description: "chart.js < 4.4.2 is vulnerable to prototype pollution via object merge in config processing.",
  },
  {
    name: "path-to-regexp",
    detect: /pathToRegexp|path-to-regexp/,
    versionExtract: /path-to-regexp[./\s]*v?(\d+\.\d+\.\d+)/i,
    vulnerableBelow: "6.3.0",
    severity: "high",
    cve: "CVE-2024-45296",
    description: "path-to-regexp < 6.3.0 is vulnerable to ReDoS that can cause server denial-of-service via crafted URL paths.",
  },
  {
    name: "cookie",
    detect: /["\s]cookie[./]|cookie\.parse|cookie\.serialize/,
    versionExtract: /cookie[./\s]*v?(\d+\.\d+\.\d+)/i,
    vulnerableBelow: "0.7.0",
    severity: "medium",
    cve: "CVE-2024-47764",
    description: "cookie < 0.7.0 accepts cookie names and values with out-of-bounds characters, enabling injection attacks.",
  },
  {
    name: "micromatch",
    detect: /micromatch[./]/,
    versionExtract: /micromatch[./\s]*v?(\d+\.\d+\.\d+)/i,
    vulnerableBelow: "4.0.8",
    severity: "medium",
    cve: "CVE-2024-4067",
    description: "micromatch < 4.0.8 is vulnerable to ReDoS when processing crafted glob patterns.",
  },
  {
    name: "tar",
    detect: /["\s]tar[./]|tar\.extract|tar\.create/,
    versionExtract: /tar[./\s]*v?(\d+\.\d+\.\d+)/i,
    vulnerableBelow: "6.2.1",
    severity: "high",
    cve: "CVE-2024-28863",
    description: "tar < 6.2.1 is vulnerable to denial of service via crafted tar headers that cause excessive memory consumption.",
  },
  {
    name: "xml2js",
    detect: /xml2js/,
    versionExtract: /xml2js[./\s]*v?(\d+\.\d+\.\d+)/i,
    vulnerableBelow: "0.5.0",
    severity: "high",
    cve: "CVE-2023-0842",
    description: "xml2js < 0.5.0 is vulnerable to prototype pollution when parsing crafted XML with __proto__ attributes.",
  },
  {
    name: "fast-xml-parser",
    detect: /fast-xml-parser|XMLParser/,
    versionExtract: /fast-xml-parser[./\s]*v?(\d+\.\d+\.\d+)/i,
    vulnerableBelow: "4.4.1",
    severity: "high",
    cve: "CVE-2024-41818",
    description: "fast-xml-parser < 4.4.1 is vulnerable to prototype pollution via __proto__ or constructor attributes in XML.",
  },
  {
    name: "undici",
    detect: /undici/,
    versionExtract: /undici[./\s]*v?(\d+\.\d+\.\d+)/i,
    vulnerableBelow: "5.28.4",
    severity: "medium",
    cve: "CVE-2024-24758",
    description: "undici < 5.28.4 leaks proxy-authorization headers across redirects to different origins.",
  },
  {
    name: "jose",
    detect: /["\s]jose[./]|jose\.jwtVerify|jose\.SignJWT/,
    versionExtract: /jose[./\s]*v?(\d+\.\d+\.\d+)/i,
    vulnerableBelow: "4.15.5",
    severity: "medium",
    cve: "CVE-2024-28176",
    description: "jose < 4.15.5 is vulnerable to denial of service when decrypting JWE with crafted headers.",
  },
];

// Detect library versions from common bundle patterns
const BUNDLE_VERSION_PATTERNS = [
  // Webpack banner comments: /*! library v1.2.3 */
  /\/\*!?\s*(\w[\w.-]*)\s+v?([\d]+\.[\d]+\.[\d]+)/g,
  // package.json-style: "name":"library","version":"1.2.3"
  /"name"\s*:\s*"([^"]+)"[^}]*"version"\s*:\s*"([\d]+\.[\d]+\.[\d]+)"/g,
  // Common global assignments: Library.VERSION = "1.2.3"
  /(\w+)\.VERSION\s*=\s*["']([\d]+\.[\d]+\.[\d]+)["']/g,
  // ESM build info: __version__ = "1.2.3"
  /(?:__version__|version)\s*(?:=|:)\s*["']([\d]+\.[\d]+\.[\d]+)["']/g,
];

const semverLt = (a: string, b: string): boolean => {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) < (pb[i] || 0)) return true;
    if ((pa[i] || 0) > (pb[i] || 0)) return false;
  }
  return false;
};

export const dependenciesModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const allJs = Array.from(target.jsContents.values()).join("\n");
  if (allJs.length === 0) return findings;

  const detectedLibs: { name: string; version: string; cve: string; severity: Finding["severity"]; description: string }[] = [];
  const seen = new Set<string>();

  // Check known vulnerable libraries
  for (const lib of VULNERABLE_LIBS) {
    if (!lib.detect.test(allJs)) continue;
    const versionMatch = allJs.match(lib.versionExtract);
    if (!versionMatch) continue;
    const version = versionMatch[1] || versionMatch[2];
    if (!version || !/^\d+\.\d+\.\d+$/.test(version)) continue;
    if (semverLt(version, lib.vulnerableBelow) && !seen.has(lib.name)) {
      seen.add(lib.name);
      detectedLibs.push({
        name: lib.name,
        version,
        cve: lib.cve,
        severity: lib.severity,
        description: lib.description,
      });
    }
  }

  // Also scan for any version strings in bundle comments
  const discoveredVersions: { name: string; version: string }[] = [];
  for (const pattern of BUNDLE_VERSION_PATTERNS) {
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(allJs)) !== null) {
      const name = match[1]?.toLowerCase();
      const version = match[2] || match[1];
      if (name && version && /^\d/.test(version)) {
        discoveredVersions.push({ name, version });
      }
    }
  }

  if (detectedLibs.length > 0) {
    for (const lib of detectedLibs.slice(0, 5)) {
      findings.push({
        id: `dep-vuln-${lib.name.toLowerCase().replace(/[^a-z0-9]/g, "-")}`,
        module: "Dependencies",
        severity: lib.severity,
        title: `Vulnerable ${lib.name} ${lib.version} in client bundle`,
        description: lib.description,
        evidence: `Library: ${lib.name} v${lib.version}\nCVE: ${lib.cve}`,
        remediation: `Update ${lib.name} to the latest version. Run: npm update ${lib.name.toLowerCase()}`,
        cwe: "CWE-1395",
        owasp: "A06:2021",
        codeSnippet: `# Update vulnerable dependency\nnpm update ${lib.name.toLowerCase()}\n# Or pin to latest safe version:\nnpm install ${lib.name.toLowerCase()}@latest`,
      });
    }
  }

  // Report discovered library versions for visibility (cross-ref with vuln db)
  const uniqueDiscovered = discoveredVersions.filter((d) => !seen.has(d.name) && !seen.has(d.name.replace(/[.-]/g, "")));
  const deduped = new Map<string, string>();
  for (const d of uniqueDiscovered) {
    if (!deduped.has(d.name)) deduped.set(d.name, d.version);
  }
  if (deduped.size > 0 && findings.length === 0) {
    findings.push({
      id: "dep-inventory",
      module: "Dependencies",
      severity: "info",
      title: `${deduped.size} client-side ${deduped.size === 1 ? "library" : "libraries"} detected`,
      description: `Detected library versions in JavaScript bundles. While no known vulnerabilities were found, keeping dependencies updated is important for security.`,
      evidence: [...deduped.entries()].slice(0, 15).map(([n, v]) => `${n} v${v}`).join("\n"),
      remediation: "Regularly audit dependencies with npm audit and keep them updated.",
    });
  }

  return findings;
};
