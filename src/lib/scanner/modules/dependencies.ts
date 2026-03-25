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
      });
    }
  }

  return findings;
};
