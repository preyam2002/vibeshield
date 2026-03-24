import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

const COMMON_COLLECTIONS = [
  "users", "profiles", "posts", "comments", "messages",
  "orders", "payments", "products", "settings", "configs",
  "notifications", "teams", "documents", "files", "events",
];

export const firebaseModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const allJs = Array.from(target.jsContents.values()).join("\n");

  // Extract Firebase config
  const projectIdMatch = allJs.match(/["']([a-z0-9-]+)\.firebaseapp\.com["']/);
  const apiKeyMatch = allJs.match(/AIza[0-9A-Za-z_-]{35}/);

  if (!projectIdMatch && !apiKeyMatch) return findings;

  const projectId = projectIdMatch?.[1];
  const apiKey = apiKeyMatch?.[0];

  // Test Realtime Database
  if (projectId) {
    const rtdbUrl = `https://${projectId}-default-rtdb.firebaseio.com`;

    try {
      // Test read access to root
      const res = await scanFetch(`${rtdbUrl}/.json?shallow=true`);
      if (res.ok) {
        const data = await res.json();
        if (data && typeof data === "object") {
          const keys = Object.keys(data);
          findings.push({
            id: "firebase-rtdb-open-read",
            module: "Firebase",
            severity: "critical",
            title: "Firebase Realtime Database is world-readable",
            description: `The Realtime Database has no security rules restricting read access. Found ${keys.length} top-level collections: ${keys.slice(0, 5).join(", ")}${keys.length > 5 ? "..." : ""}`,
            evidence: `GET ${rtdbUrl}/.json?shallow=true\nCollections: ${keys.join(", ")}`,
            remediation: 'Add security rules: { "rules": { ".read": "auth != null", ".write": "auth != null" } }',
            cwe: "CWE-862",
            owasp: "A01:2021",
          });
        }
      }
    } catch {
      // RTDB might not exist
    }

    // Test write access
    try {
      const res = await scanFetch(`${rtdbUrl}/_vibeshield_test.json`, {
        method: "PUT",
        body: JSON.stringify({ test: true, timestamp: Date.now() }),
      });
      if (res.ok) {
        // Clean up
        await scanFetch(`${rtdbUrl}/_vibeshield_test.json`, { method: "DELETE" });
        findings.push({
          id: "firebase-rtdb-open-write",
          module: "Firebase",
          severity: "critical",
          title: "Firebase Realtime Database allows anonymous writes",
          description: "Anyone can write arbitrary data to your database without authentication. Attackers can inject malicious data, overwrite existing records, or fill your database with garbage.",
          evidence: `PUT ${rtdbUrl}/_vibeshield_test.json → 200 OK`,
          remediation: 'Set write rules: { "rules": { ".write": "auth != null" } }',
          cwe: "CWE-862",
          owasp: "A01:2021",
        });
      }
    } catch {
      // fine
    }
  }

  // Test Firestore REST API
  if (projectId && apiKey) {
    for (const collection of COMMON_COLLECTIONS) {
      try {
        const firestoreUrl = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${collection}?pageSize=3&key=${apiKey}`;
        const res = await scanFetch(firestoreUrl);
        if (res.ok) {
          const data = await res.json() as { documents?: unknown[] };
          if (data.documents && data.documents.length > 0) {
            findings.push({
              id: `firebase-firestore-read-${collection}`,
              module: "Firebase",
              severity: "critical",
              title: `Firestore collection "${collection}" is world-readable`,
              description: `The "${collection}" collection returned ${data.documents.length} documents without authentication. Anyone can read this data.`,
              evidence: `GET firestore.googleapis.com/.../documents/${collection}\nDocuments returned: ${data.documents.length}`,
              remediation: `Add Firestore security rules:\nrules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents/${collection}/{doc} {\n    allow read: if request.auth != null;\n  }\n}`,
              cwe: "CWE-862",
              owasp: "A01:2021",
            });
          }
        }
      } catch {
        // skip
      }
    }

    // Test Firestore write access
    try {
      const writeUrl = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/_vibeshield_test?key=${apiKey}`;
      const res = await scanFetch(writeUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          fields: { test: { booleanValue: true } },
        }),
      });
      if (res.ok) {
        findings.push({
          id: "firebase-firestore-open-write",
          module: "Firebase",
          severity: "critical",
          title: "Firestore allows anonymous document creation",
          description: "Anyone can create new documents in Firestore without authentication.",
          evidence: `POST to _vibeshield_test collection succeeded`,
          remediation: "Add Firestore rules to restrict write access to authenticated users.",
          cwe: "CWE-862",
        });
      }
    } catch {
      // fine
    }
  }

  // Test Firebase Storage
  if (projectId) {
    try {
      const storageUrl = `https://firebasestorage.googleapis.com/v0/b/${projectId}.firebasestorage.app/o?maxResults=5`;
      const res = await scanFetch(storageUrl);
      if (res.ok) {
        const data = await res.json() as { items?: { name: string }[] };
        if (data.items && data.items.length > 0) {
          findings.push({
            id: "firebase-storage-listable",
            module: "Firebase",
            severity: "high",
            title: "Firebase Storage bucket is listable",
            description: `Storage bucket contents are publicly listable. Found ${data.items.length} files: ${data.items.map((i) => i.name).slice(0, 3).join(", ")}`,
            evidence: `Bucket: ${projectId}.appspot.com\nFiles: ${data.items.map((i) => i.name).join(", ")}`,
            remediation: "Add Storage security rules to restrict listing and access.",
            cwe: "CWE-862",
          });
        }
      }
    } catch {
      // skip
    }
  }

  return findings;
};
