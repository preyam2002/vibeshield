import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

export const storageModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const allJs = Array.from(target.jsContents.values()).join("\n");

  // Detect S3 bucket URLs in JS bundles
  const s3Patterns = [
    /https?:\/\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3[.-][\w-]+\.amazonaws\.com/gi,
    /https?:\/\/s3[.-][\w-]+\.amazonaws\.com\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])/gi,
  ];

  const bucketUrls = new Set<string>();
  for (const pattern of s3Patterns) {
    let m;
    while ((m = pattern.exec(allJs)) !== null) {
      bucketUrls.add(m[0]);
    }
  }

  // Detect GCS bucket URLs
  const gcsPattern = /https?:\/\/storage\.googleapis\.com\/([a-z0-9][a-z0-9._-]{1,61}[a-z0-9])/gi;
  let gcsMatch;
  while ((gcsMatch = gcsPattern.exec(allJs)) !== null) {
    bucketUrls.add(gcsMatch[0]);
  }

  // Detect Azure Blob Storage URLs
  const azurePattern = /https?:\/\/([a-z0-9]{3,24})\.blob\.core\.windows\.net\/([a-z0-9][a-z0-9-]{1,61}[a-z0-9])/gi;
  let azureMatch;
  while ((azureMatch = azurePattern.exec(allJs)) !== null) {
    bucketUrls.add(azureMatch[0]);
  }

  // Detect R2/Cloudflare storage
  const r2Pattern = /https?:\/\/[a-f0-9]{32}\.r2\.cloudflarestorage\.com\/([a-z0-9][a-z0-9-]{1,61})/gi;
  let r2Match;
  while ((r2Match = r2Pattern.exec(allJs)) !== null) {
    bucketUrls.add(r2Match[0]);
  }

  // Detect DigitalOcean Spaces
  const doPattern = /https?:\/\/([a-z0-9][a-z0-9-]{1,61})\.([a-z0-9-]+)\.digitaloceanspaces\.com/gi;
  let doMatch;
  while ((doMatch = doPattern.exec(allJs)) !== null) {
    bucketUrls.add(doMatch[0]);
  }

  // Detect Backblaze B2
  const b2Pattern = /https?:\/\/f\d{3}\.backblazeb2\.com\/file\/([a-zA-Z0-9-]+)/gi;
  let b2Match;
  while ((b2Match = b2Pattern.exec(allJs)) !== null) {
    bucketUrls.add(b2Match[0]);
  }

  // Detect Wasabi
  const wasabiPattern = /https?:\/\/s3\.([a-z0-9-]+)\.wasabisys\.com\/([a-z0-9][a-z0-9.-]+)/gi;
  let wasabiMatch;
  while ((wasabiMatch = wasabiPattern.exec(allJs)) !== null) {
    bucketUrls.add(wasabiMatch[0]);
  }

  // Detect MinIO
  const minioPattern = /https?:\/\/[a-z0-9.-]+(?::\d+)?\/([a-z0-9][a-z0-9.-]+)(?=\/)/gi;
  // Only add MinIO if URL contains minio indicator
  const minioUrls = allJs.match(/https?:\/\/[a-z0-9.-]+(?::\d+)?\/[a-z0-9][a-z0-9.-]+/gi);
  if (minioUrls) {
    for (const url of minioUrls) {
      if (/minio/i.test(url)) bucketUrls.add(url);
    }
  }

  if (bucketUrls.size === 0) return findings;

  const bucketSlice = [...bucketUrls].slice(0, 5);

  // Test bucket CORS — wildcard origin on storage endpoints enables credential theft
  const corsResults = await Promise.allSettled(
    bucketSlice.map(async (url) => {
      const baseUrl = url.replace(/\/[^/]*\.[^/]*$/, "/");
      const res = await scanFetch(baseUrl, {
        headers: { Origin: "https://evil.example.com" },
        timeoutMs: 8000,
      });
      const acao = res.headers.get("access-control-allow-origin") || "";
      const acac = res.headers.get("access-control-allow-credentials") || "";
      if (acao === "*" || acao === "https://evil.example.com") {
        return { url: baseUrl, origin: acao, credentials: acac.toLowerCase() === "true" };
      }
      return null;
    }),
  );

  for (const r of corsResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    const isReflected = v.origin === "https://evil.example.com";
    findings.push({
      id: `storage-cors-${findings.length}`,
      module: "Cloud Storage",
      severity: v.credentials ? "critical" : "high",
      title: `Storage bucket CORS allows ${isReflected ? "reflected" : "wildcard"} origin`,
      description: `The bucket at ${v.url} returns Access-Control-Allow-Origin: ${v.origin}${v.credentials ? " with credentials allowed" : ""}. ${isReflected ? "Any website can read bucket contents on behalf of authenticated users." : "Any origin can make cross-origin requests to this bucket."}`,
      evidence: `GET ${v.url}\nOrigin: https://evil.example.com\nAccess-Control-Allow-Origin: ${v.origin}${v.credentials ? "\nAccess-Control-Allow-Credentials: true" : ""}`,
      remediation: "Restrict CORS origins to your app's domain. Never use wildcard origin with credentials.",
      cwe: "CWE-942",
      owasp: "A05:2021",
    });
  }

  // Test public write access — attempt PUT on bucket (non-destructive: uses .vibeshield-test key)
  const writeResults = await Promise.allSettled(
    bucketSlice.map(async (url) => {
      const baseUrl = url.replace(/\/[^/]*\.[^/]*$/, "/");
      const testKey = ".vibeshield-write-test";
      const testUrl = `${baseUrl}${testKey}`;
      const res = await scanFetch(testUrl, {
        method: "PUT",
        headers: { "Content-Type": "text/plain" },
        body: "vibeshield-test",
        timeoutMs: 8000,
      });
      if (res.ok || res.status === 200 || res.status === 204) {
        // Clean up: try to delete the test object
        await scanFetch(testUrl, { method: "DELETE", timeoutMs: 5000 }).catch(() => {});
        return { url: baseUrl, status: res.status };
      }
      return null;
    }),
  );

  for (const r of writeResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `storage-public-write-${findings.length}`,
      module: "Cloud Storage",
      severity: "critical",
      title: "Cloud storage bucket allows anonymous write access",
      description: `The bucket at ${v.url} accepts PUT requests without authentication. Attackers can upload arbitrary files, potentially serving malware, phishing pages, or overwriting legitimate assets.`,
      evidence: `PUT ${v.url}.vibeshield-write-test → ${v.status}`,
      remediation: "Disable public write access immediately. Use server-side presigned URLs for uploads with strict content-type and size limits.",
      cwe: "CWE-284",
      owasp: "A01:2021",
      codeSnippet: `// Use presigned URLs for controlled uploads\nimport { getSignedUrl } from "@aws-sdk/s3-request-presigner";\nconst url = await getSignedUrl(s3, new PutObjectCommand({\n  Bucket: process.env.S3_BUCKET,\n  Key: \`uploads/\${crypto.randomUUID()}\`,\n  ContentType: "image/jpeg",\n  // Enforce max size via conditions\n}), { expiresIn: 300 });`,
    });
  }

  // Test S3 ACL exposure — ?acl endpoint reveals bucket permissions
  const aclResults = await Promise.allSettled(
    bucketSlice.filter((u) => /amazonaws\.com/i.test(u)).map(async (url) => {
      const baseUrl = url.replace(/\/[^/]*\.[^/]*$/, "/");
      const res = await scanFetch(`${baseUrl}?acl`, { timeoutMs: 8000 });
      if (!res.ok) return null;
      const text = await res.text();
      if (text.includes("<AccessControlPolicy") || text.includes("<Grant>")) {
        const hasAllUsers = text.includes("AllUsers") || text.includes("AuthenticatedUsers");
        return { url: baseUrl, hasAllUsers };
      }
      return null;
    }),
  );

  for (const r of aclResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `storage-acl-exposed-${findings.length}`,
      module: "Cloud Storage",
      severity: v.hasAllUsers ? "high" : "medium",
      title: `S3 bucket ACL publicly readable${v.hasAllUsers ? " — grants to AllUsers/AuthenticatedUsers" : ""}`,
      description: `The bucket at ${v.url} exposes its ACL via ?acl. ${v.hasAllUsers ? "The ACL grants access to AllUsers or AuthenticatedUsers, meaning anyone can access this bucket." : "While the ACL itself may not grant public access, exposing it reveals the bucket's permission structure."}`,
      evidence: `GET ${v.url}?acl → 200 (AccessControlPolicy)`,
      remediation: "Block public ACL reads. In S3, enable 'Block Public Access' settings at the bucket or account level.",
      cwe: "CWE-732",
      owasp: "A01:2021",
    });
  }

  // Test each bucket for public listing (directory listing enabled)
  const listResults = await Promise.allSettled(
    [...bucketUrls].slice(0, 5).map(async (url) => {
      // Try to list the bucket (S3/GCS XML listing)
      const baseUrl = url.replace(/\/[^/]*\.[^/]*$/, "/"); // strip filename if present
      const res = await scanFetch(baseUrl, { timeoutMs: 8000 });
      if (!res.ok) return null;
      const text = await res.text();
      // S3 XML listing response
      if (text.includes("<ListBucketResult") || text.includes("<Contents>")) {
        const keyMatches = text.match(/<Key>[^<]+<\/Key>/g) || [];
        return { url: baseUrl, type: "s3-listing", keys: keyMatches.length };
      }
      // GCS JSON listing
      if (text.includes('"kind": "storage#objects"') || text.includes('"items"')) {
        return { url: baseUrl, type: "gcs-listing", keys: 0 };
      }
      return null;
    }),
  );

  for (const r of listResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    findings.push({
      id: `storage-public-listing-${findings.length}`,
      module: "Cloud Storage",
      severity: "high",
      title: "Cloud storage bucket allows public listing",
      description: `The bucket at ${v.url} allows anonymous directory listing. Anyone can enumerate all files in this bucket, potentially exposing user uploads, backups, or private assets.${v.keys > 0 ? ` Found ${v.keys} objects listed.` : ""}`,
      evidence: `GET ${v.url}\nResponse contains ${v.type === "s3-listing" ? "S3 ListBucketResult" : "GCS storage#objects"} XML`,
      remediation: "Disable public listing on your bucket. Use signed URLs for file access.",
      cwe: "CWE-532",
      owasp: "A01:2021",
      codeSnippet: `// AWS S3: block public access\n{\n  "BlockPublicAcls": true,\n  "IgnorePublicAcls": true,\n  "BlockPublicPolicy": true,\n  "RestrictPublicBuckets": true\n}\n\n// Or use signed URLs for access\nimport { getSignedUrl } from "@aws-sdk/s3-request-presigner";\nconst url = await getSignedUrl(s3, new GetObjectCommand({ Bucket: "...", Key: "..." }), { expiresIn: 3600 });`,
    });
  }

  // Check for presigned URL patterns that might be too long-lived or leaked
  const presignedPatterns = [
    /X-Amz-Expires=(\d+)/g,
    /se=(\d{4}-\d{2}-\d{2})/g, // Azure SAS token expiry
  ];
  for (const pattern of presignedPatterns) {
    let pm;
    while ((pm = pattern.exec(allJs)) !== null) {
      if (pattern.source.includes("Amz-Expires")) {
        const seconds = parseInt(pm[1], 10);
        if (seconds > 86400) { // More than 24 hours
          findings.push({
            id: "storage-long-presigned",
            module: "Cloud Storage",
            severity: "medium",
            title: "Presigned URL with excessive expiry found in JS bundle",
            description: `Found a presigned S3 URL with X-Amz-Expires=${seconds} (${Math.round(seconds / 3600)} hours). Long-lived presigned URLs can be shared and abused after the intended access window.`,
            evidence: `X-Amz-Expires=${seconds} (${Math.round(seconds / 86400)} days)`,
            remediation: "Generate presigned URLs on the server with short expiry (1 hour or less). Never embed them in client-side JS bundles.",
            cwe: "CWE-798",
          });
          break;
        }
      }
    }
  }

  // Check pre-signed URLs in API responses for excessive expiry or missing IP binding
  const apiEndpointsToTest = target.apiEndpoints.slice(0, 10);
  const presignedUrlResults = await Promise.allSettled(
    apiEndpointsToTest.map(async (endpoint) => {
      const res = await scanFetch(endpoint, { timeoutMs: 8000 });
      if (!res.ok) return null;
      const text = await res.text();
      // Look for pre-signed URLs in API responses
      const s3Presigned = [...text.matchAll(/https?:\/\/[^"'\s]+X-Amz-Expires=(\d+)[^"'\s]*/g)];
      const gcsSigned = [...text.matchAll(/https?:\/\/storage\.googleapis\.com\/[^"'\s]+X-Goog-Expires=(\d+)[^"'\s]*/g)];
      const azureSas = [...text.matchAll(/https?:\/\/[^"'\s]+\.blob\.core\.windows\.net\/[^"'\s]+se=(\d{4}-\d{2}-\d{2}T\d{2}%3A\d{2}%3A\d{2}Z)[^"'\s]*/g)];
      const longLived: { url: string; expirySeconds: number }[] = [];
      for (const m of s3Presigned) {
        const seconds = parseInt(m[1], 10);
        if (seconds > 86400) longLived.push({ url: m[0].substring(0, 120), expirySeconds: seconds });
      }
      for (const m of gcsSigned) {
        const seconds = parseInt(m[1], 10);
        if (seconds > 86400) longLived.push({ url: m[0].substring(0, 120), expirySeconds: seconds });
      }
      for (const m of azureSas) {
        // Azure SAS: check if expiry date is > 24h from now
        try {
          const expiry = new Date(decodeURIComponent(m[1]));
          const diffSeconds = (expiry.getTime() - Date.now()) / 1000;
          if (diffSeconds > 86400) longLived.push({ url: m[0].substring(0, 120), expirySeconds: Math.round(diffSeconds) });
        } catch { /* skip unparseable dates */ }
      }
      // Check if any presigned URL lacks IP binding (X-Amz-SignedHeaders should not contain host-only)
      const allPresigned = [...s3Presigned, ...gcsSigned];
      const lacksIpBinding = allPresigned.length > 0 && !text.includes("X-Amz-Condition") && !text.includes("aws:SourceIp");
      if (longLived.length > 0 || (allPresigned.length > 0 && lacksIpBinding)) {
        return { endpoint, longLived, lacksIpBinding, presignedCount: allPresigned.length + azureSas.length };
      }
      return null;
    }),
  );

  for (const r of presignedUrlResults) {
    if (r.status !== "fulfilled" || !r.value) continue;
    const v = r.value;
    if (v.longLived.length > 0) {
      const worst = v.longLived.reduce((a, b) => (a.expirySeconds > b.expirySeconds ? a : b));
      findings.push({
        id: `storage-presigned-long-expiry-${findings.length}`,
        module: "Cloud Storage",
        severity: "medium",
        title: "Pre-signed URL with excessive expiry in API response",
        description: `The API endpoint ${v.endpoint} returns pre-signed URLs with expiry up to ${Math.round(worst.expirySeconds / 3600)} hours. Long-lived pre-signed URLs can be shared, cached, or leaked via referrer headers long after access should have expired.`,
        evidence: `GET ${v.endpoint}\nPre-signed URL: ${worst.url}...\nExpiry: ${worst.expirySeconds}s (${Math.round(worst.expirySeconds / 3600)}h)`,
        remediation: "Generate pre-signed URLs with short expiry (15 minutes to 1 hour max). For downloads, generate URLs on demand. Never cache or embed them in HTML.",
        cwe: "CWE-613",
      });
    }
    if (v.lacksIpBinding && v.presignedCount > 0) {
      findings.push({
        id: `storage-presigned-no-ip-bind-${findings.length}`,
        module: "Cloud Storage",
        severity: "low",
        title: "Pre-signed URLs lack IP binding",
        description: `The API endpoint ${v.endpoint} returns ${v.presignedCount} pre-signed URL(s) without IP-based access conditions. Anyone who obtains the URL (via logs, referrer leaks, or shared links) can use it from any network.`,
        evidence: `GET ${v.endpoint}\nPre-signed URLs found: ${v.presignedCount}\nNo aws:SourceIp condition or equivalent detected`,
        remediation: "Add IP-based conditions to pre-signed URLs using policy conditions (e.g., aws:SourceIp for S3). This limits URL usage to the requesting client's IP.",
        cwe: "CWE-284",
      });
    }
  }

  // CDN/blob URL enumeration — test if sequential IDs or incrementing blob names expose other users' files
  const blobUrlPatterns = [
    /https?:\/\/[^"'\s]+\/(?:uploads?|files?|media|blobs?|assets?)\/(\d+)/g,
    /https?:\/\/[^"'\s]+\/(?:uploads?|files?|media|blobs?|assets?)\/([a-z]+\d+)/g,
  ];
  const sequentialUrls = new Set<{ baseUrl: string; id: string; full: string }>();
  for (const pattern of blobUrlPatterns) {
    for (const m of allJs.matchAll(pattern)) {
      sequentialUrls.add({ baseUrl: m[0].replace(m[1], ""), id: m[1], full: m[0] });
    }
  }

  const enumSlice = [...sequentialUrls].slice(0, 5);
  if (enumSlice.length > 0) {
    const enumResults = await Promise.allSettled(
      enumSlice.map(async (entry) => {
        // Try incrementing and decrementing the ID
        const numericId = parseInt(entry.id.replace(/[^0-9]/g, ""), 10);
        if (isNaN(numericId)) return null;
        const prefix = entry.id.replace(/\d+/, "");
        const testIds = [numericId + 1, numericId - 1, numericId + 100].filter((n) => n > 0);
        const accessible: string[] = [];
        for (const testId of testIds) {
          const testUrl = entry.baseUrl + prefix + testId;
          try {
            const res = await scanFetch(testUrl, { timeoutMs: 5000 });
            if (res.ok) {
              const ct = res.headers.get("content-type") || "";
              // Only count if it looks like real content (not HTML error pages)
              if (!ct.includes("text/html")) accessible.push(testUrl);
            }
          } catch { /* skip */ }
        }
        if (accessible.length > 0) return { original: entry.full, accessible };
        return null;
      }),
    );

    for (const r of enumResults) {
      if (r.status !== "fulfilled" || !r.value) continue;
      const v = r.value;
      findings.push({
        id: `storage-blob-enumeration-${findings.length}`,
        module: "Cloud Storage",
        severity: "high",
        title: "CDN/blob URL enumeration exposes other files",
        description: `Sequential IDs in blob/file URLs allow enumeration. Starting from ${v.original}, incrementing the ID exposed ${v.accessible.length} other file(s). Attackers can scrape all user-uploaded content by iterating IDs.`,
        evidence: `Original URL: ${v.original}\nEnumerated:\n${v.accessible.slice(0, 3).join("\n")}`,
        remediation: "Use UUIDs or cryptographic random tokens for file identifiers instead of sequential IDs. Add per-user authorization checks on file access endpoints.",
        cwe: "CWE-639",
        owasp: "A01:2021",
        codeSnippet: `// Use UUIDs instead of sequential IDs\nimport crypto from 'crypto';\nconst fileKey = crypto.randomUUID(); // e.g., "a1b2c3d4-e5f6-..."`,
      });
    }
  }

  // Storage CORS misconfiguration — check storage endpoints found in pages for overly permissive CORS
  const storageEndpointPatterns = [
    /https?:\/\/[a-z0-9.-]+\.s3[.-][\w-]+\.amazonaws\.com[^"'\s]*/gi,
    /https?:\/\/storage\.googleapis\.com\/[a-z0-9._-]+[^"'\s]*/gi,
    /https?:\/\/[a-z0-9]+\.blob\.core\.windows\.net\/[^"'\s]*/gi,
    /https?:\/\/[a-f0-9]+\.r2\.cloudflarestorage\.com\/[^"'\s]*/gi,
  ];
  const allPageContent = target.pages.join("\n");
  const storageEndpointsInPages = new Set<string>();
  for (const pat of storageEndpointPatterns) {
    for (const m of allPageContent.matchAll(pat)) {
      // Normalize to base path (strip query params and trailing file for CORS check)
      const cleaned = m[0].split("?")[0].replace(/\/[^/]*\.[^/]*$/, "/");
      storageEndpointsInPages.add(cleaned);
    }
  }
  // Also check JS bundle for storage URLs not yet tested
  for (const pat of storageEndpointPatterns) {
    for (const m of allJs.matchAll(pat)) {
      const cleaned = m[0].split("?")[0].replace(/\/[^/]*\.[^/]*$/, "/");
      storageEndpointsInPages.add(cleaned);
    }
  }

  // Deduplicate against already-tested bucketSlice
  const corsEndpoints = [...storageEndpointsInPages].filter((u) => !bucketSlice.includes(u)).slice(0, 5);
  if (corsEndpoints.length > 0) {
    const pageCorsResults = await Promise.allSettled(
      corsEndpoints.map(async (url) => {
        // Send OPTIONS preflight with a suspicious origin
        const res = await scanFetch(url, {
          method: "OPTIONS",
          headers: {
            Origin: "https://attacker.example.com",
            "Access-Control-Request-Method": "GET",
          },
          timeoutMs: 8000,
        });
        const acao = res.headers.get("access-control-allow-origin") || "";
        const acam = res.headers.get("access-control-allow-methods") || "";
        const acac = res.headers.get("access-control-allow-credentials") || "";
        if (acao === "*" || acao === "https://attacker.example.com") {
          return { url, origin: acao, methods: acam, credentials: acac.toLowerCase() === "true" };
        }
        return null;
      }),
    );

    for (const r of pageCorsResults) {
      if (r.status !== "fulfilled" || !r.value) continue;
      const v = r.value;
      findings.push({
        id: `storage-page-cors-${findings.length}`,
        module: "Cloud Storage",
        severity: v.credentials ? "critical" : "medium",
        title: `Storage endpoint CORS misconfiguration${v.credentials ? " with credentials" : ""}`,
        description: `The storage endpoint ${v.url} responds to preflight requests with Access-Control-Allow-Origin: ${v.origin}${v.methods ? ` and allows methods: ${v.methods}` : ""}. ${v.credentials ? "Combined with Allow-Credentials: true, any website can read storage content on behalf of authenticated users." : "Any origin can make cross-origin requests to this storage endpoint."}`,
        evidence: `OPTIONS ${v.url}\nOrigin: https://attacker.example.com\nAccess-Control-Allow-Origin: ${v.origin}${v.methods ? `\nAccess-Control-Allow-Methods: ${v.methods}` : ""}${v.credentials ? "\nAccess-Control-Allow-Credentials: true" : ""}`,
        remediation: "Configure CORS on your storage bucket to only allow your application's origin. Never use wildcard origin with credentials. Restrict allowed methods to GET only if writes aren't needed.",
        cwe: "CWE-942",
        owasp: "A05:2021",
      });
    }
  }

  // Check for hardcoded storage credentials in JS
  const storageCredPatterns = [
    { name: "AWS Access Key", pattern: /(?:AKIA|ASIA)[A-Z0-9]{16}/ },
    { name: "Azure Storage Key", pattern: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{86,}/ },
    { name: "GCS Service Account", pattern: /"type"\s*:\s*"service_account"[\s\S]{0,100}"private_key"/ },
  ];
  for (const { name, pattern } of storageCredPatterns) {
    if (pattern.test(allJs)) {
      findings.push({
        id: `storage-cred-${name.toLowerCase().replace(/\s+/g, "-")}`,
        module: "Cloud Storage",
        severity: "critical",
        title: `${name} found in JavaScript bundle`,
        description: `A ${name} is exposed in client-side JavaScript. This grants direct access to your cloud storage and potentially other cloud services.`,
        remediation: "Remove the credential from client code immediately. Rotate the key. Use server-side API routes to proxy storage operations.",
        cwe: "CWE-798",
        owasp: "A02:2021",
        codeSnippet: `// Server-side upload proxy\nexport async function POST(req: Request) {\n  const { filename } = await req.json();\n  const url = await getSignedUrl(s3, new PutObjectCommand({\n    Bucket: process.env.S3_BUCKET,\n    Key: \`uploads/\${filename}\`,\n  }), { expiresIn: 300 });\n  return Response.json({ uploadUrl: url });\n}`,
      });
    }
  }

  return findings;
};
