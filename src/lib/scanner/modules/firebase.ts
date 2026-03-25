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
  const rtdbUrl = projectId ? `https://${projectId}-default-rtdb.firebaseio.com` : null;

  // Run all Firebase tests in parallel
  const [rtdbReadResult, rtdbWriteResult, firestoreResults, firestoreWriteResult, storageResult] = await Promise.all([
    // RTDB read
    rtdbUrl ? scanFetch(`${rtdbUrl}/.json?shallow=true`).then(async (res) => {
      if (!res.ok) return null;
      const data = await res.json();
      if (data && typeof data === "object") return Object.keys(data);
      return null;
    }).catch(() => null) : Promise.resolve(null),

    // RTDB write
    rtdbUrl ? scanFetch(`${rtdbUrl}/_vibeshield_test.json`, { method: "PUT", body: JSON.stringify({ test: true, timestamp: Date.now() }) }).then(async (res) => {
      if (res.ok) { scanFetch(`${rtdbUrl}/_vibeshield_test.json`, { method: "DELETE" }).catch(() => {}); return true; }
      return false;
    }).catch(() => false) : Promise.resolve(false),

    // Firestore collection reads — all in parallel
    (projectId && apiKey) ? Promise.allSettled(
      COMMON_COLLECTIONS.map(async (collection) => {
        const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${collection}?pageSize=3&key=${apiKey}`;
        const res = await scanFetch(url);
        if (!res.ok) return null;
        const data = await res.json() as { documents?: unknown[] };
        if (data.documents && data.documents.length > 0) return { collection, count: data.documents.length };
        return null;
      }),
    ) : Promise.resolve([]),

    // Firestore write
    (projectId && apiKey) ? scanFetch(`https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/_vibeshield_test?key=${apiKey}`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ fields: { test: { booleanValue: true } } }),
    }).then((res) => res.ok).catch(() => false) : Promise.resolve(false),

    // Firebase Storage
    projectId ? scanFetch(`https://firebasestorage.googleapis.com/v0/b/${projectId}.firebasestorage.app/o?maxResults=5`).then(async (res) => {
      if (!res.ok) return null;
      const data = await res.json() as { items?: { name: string }[] };
      if (data.items && data.items.length > 0) return data.items;
      return null;
    }).catch(() => null) : Promise.resolve(null),
  ]);

  // Collect findings
  if (rtdbReadResult && rtdbUrl) {
    findings.push({
      id: "firebase-rtdb-open-read", module: "Firebase", severity: "critical",
      title: "Firebase Realtime Database is world-readable",
      description: `The Realtime Database has no security rules restricting read access. Found ${rtdbReadResult.length} top-level collections: ${rtdbReadResult.slice(0, 5).join(", ")}${rtdbReadResult.length > 5 ? "..." : ""}`,
      evidence: `GET ${rtdbUrl}/.json?shallow=true\nCollections: ${rtdbReadResult.join(", ")}`,
      remediation: 'Add security rules: { "rules": { ".read": "auth != null", ".write": "auth != null" } }',
      cwe: "CWE-862", owasp: "A01:2021",
      codeSnippet: `// firebase-database.rules.json\n{\n  "rules": {\n    ".read": "auth != null",\n    ".write": "auth != null"\n  }\n}`,
    });
  }
  if (rtdbWriteResult && rtdbUrl) {
    findings.push({
      id: "firebase-rtdb-open-write", module: "Firebase", severity: "critical",
      title: "Firebase Realtime Database allows anonymous writes",
      description: "Anyone can write arbitrary data to your database without authentication.",
      evidence: `PUT ${rtdbUrl}/_vibeshield_test.json → 200 OK`,
      remediation: 'Set write rules: { "rules": { ".write": "auth != null" } }',
      cwe: "CWE-862", owasp: "A01:2021",
      codeSnippet: `// firebase-database.rules.json\n{\n  "rules": {\n    ".read": "auth != null",\n    ".write": "auth != null"\n  }\n}`,
    });
  }
  for (const r of firestoreResults) {
    if ((r as PromiseSettledResult<{ collection: string; count: number } | null>).status !== "fulfilled") continue;
    const v = (r as PromiseFulfilledResult<{ collection: string; count: number } | null>).value;
    if (!v) continue;
    findings.push({
      id: `firebase-firestore-read-${v.collection}`, module: "Firebase", severity: "critical",
      title: `Firestore collection "${v.collection}" is world-readable`,
      description: `The "${v.collection}" collection returned ${v.count} documents without authentication.`,
      evidence: `GET firestore.googleapis.com/.../documents/${v.collection}\nDocuments returned: ${v.count}`,
      remediation: `Add Firestore security rules to restrict read access for "${v.collection}".`,
      cwe: "CWE-862", owasp: "A01:2021",
      codeSnippet: `// firestore.rules\nrules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /${v.collection}/{docId} {\n      allow read: if request.auth != null;\n      allow write: if request.auth != null\n        && request.auth.uid == resource.data.userId;\n    }\n  }\n}`,
    });
  }
  if (firestoreWriteResult) {
    findings.push({
      id: "firebase-firestore-open-write", module: "Firebase", severity: "critical",
      title: "Firestore allows anonymous document creation",
      description: "Anyone can create new documents in Firestore without authentication.",
      evidence: "POST to _vibeshield_test collection succeeded",
      remediation: "Add Firestore rules to restrict write access to authenticated users.",
      cwe: "CWE-862",
      codeSnippet: `// firestore.rules\nrules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n    match /{collection}/{docId} {\n      allow read: if request.auth != null;\n      allow write: if request.auth != null;\n    }\n  }\n}`,
    });
  }
  if (storageResult) {
    findings.push({
      id: "firebase-storage-listable", module: "Firebase", severity: "high",
      title: "Firebase Storage bucket is listable",
      description: `Storage bucket contents are publicly listable. Found ${storageResult.length} files: ${storageResult.map((i) => i.name).slice(0, 3).join(", ")}`,
      evidence: `Bucket: ${projectId}.appspot.com\nFiles: ${storageResult.map((i) => i.name).join(", ")}`,
      remediation: "Add Storage security rules to restrict listing and access.",
      cwe: "CWE-862",
      codeSnippet: `// storage.rules\nrules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n    match /{allPaths=**} {\n      allow read, write: if request.auth != null;\n    }\n  }\n}`,
    });
  }

  return findings;
};
