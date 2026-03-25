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

  if (bucketUrls.size === 0) return findings;

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
