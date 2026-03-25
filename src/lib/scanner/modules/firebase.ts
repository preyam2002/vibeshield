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
  const [rtdbReadResult, rtdbWriteResult, firestoreResults, firestoreWriteResult, storageResult, authConfigResult] = await Promise.all([
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

    // Firebase Auth — check if email/password signup is open and if email enumeration is possible
    apiKey ? (async () => {
      const result: { signupOpen?: boolean; emailEnumerable?: boolean; providers?: string[] } = {};
      const [signupRes, lookupRes] = await Promise.allSettled([
        scanFetch(`https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${apiKey}`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ returnSecureToken: true }),
        }),
        scanFetch(`https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key=${apiKey}`, {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ identifier: "test@example.com", continueUri: "http://localhost" }),
        }),
      ]);
      if (signupRes.status === "fulfilled") {
        const data = await signupRes.value.json() as { localId?: string; error?: { message?: string } };
        if (data.localId) result.signupOpen = true;
      }
      if (lookupRes.status === "fulfilled" && lookupRes.value.ok) {
        const data = await lookupRes.value.json() as { registered?: boolean; allProviders?: string[] };
        if (typeof data.registered === "boolean") {
          result.emailEnumerable = true;
          if (data.allProviders) result.providers = data.allProviders;
        }
      }
      return result;
    })() : Promise.resolve(null),
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

  // Test Cloud Functions for missing auth
  if (projectId) {
    const cloudFnPaths = [
      "api", "webhook", "onRequest", "processPayment", "sendEmail", "createUser",
      "generate", "chat", "notify", "sync", "stripe", "cron",
    ];
    // Discover function names from JS bundles
    const fnRegions = ["us-central1", "us-east1", "europe-west1"];
    const cfMatches = allJs.matchAll(/cloudfunctions\.net\/([a-zA-Z0-9_-]+)/g);
    for (const m of cfMatches) {
      if (!cloudFnPaths.includes(m[1])) cloudFnPaths.push(m[1]);
    }
    // Also look for callable function references
    const callableMatches = allJs.matchAll(/httpsCallable\s*\(\s*[^,]*,\s*["']([^"']+)["']/g);
    for (const m of callableMatches) {
      if (!cloudFnPaths.includes(m[1])) cloudFnPaths.push(m[1]);
    }

    const cloudFnResults = await Promise.allSettled(
      cloudFnPaths.flatMap((fn) =>
        fnRegions.slice(0, 1).map(async (region) => {
          const url = `https://${region}-${projectId}.cloudfunctions.net/${fn}`;
          const res = await scanFetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ data: { test: true } }),
            timeoutMs: 8000,
          });
          if (res.status === 404 || res.status === 403 || res.status === 401) return null;
          const text = await res.text();
          if (text.length < 5) return null;
          if (res.ok || res.status === 400) {
            return { fn, region, url, status: res.status, text: text.substring(0, 300) };
          }
          return null;
        }),
      ),
    );

    const cfSeen = new Set<string>();
    for (const r of cloudFnResults) {
      if (r.status !== "fulfilled" || !r.value) continue;
      const { fn, url, status, text } = r.value;
      if (cfSeen.has(fn)) continue;
      cfSeen.add(fn);
      findings.push({
        id: `firebase-cloud-fn-no-auth-${fn}`, module: "Firebase", severity: "high",
        title: `Cloud Function "${fn}" accessible without authentication`,
        description: "This Firebase Cloud Function responds to unauthenticated requests. Attackers can invoke it directly, potentially abusing server-side logic, consuming your Cloud billing quota, or accessing internal services.",
        evidence: `POST ${url}\nStatus: ${status}\nResponse: ${text}`,
        remediation: "Validate Firebase Auth tokens in your Cloud Functions. For HTTP functions, verify the Authorization header. For callable functions, use the built-in auth context.",
        cwe: "CWE-306", owasp: "A07:2021",
        codeSnippet: `// Validate auth in HTTP Cloud Functions\nexport const myFunction = onRequest(async (req, res) => {\n  const token = req.headers.authorization?.split("Bearer ")[1];\n  if (!token) { res.status(401).send("Unauthorized"); return; }\n  try {\n    const decoded = await admin.auth().verifyIdToken(token);\n    // ... handle authenticated request\n  } catch {\n    res.status(401).send("Invalid token");\n  }\n});\n\n// Or use callable functions (auth built-in):\nexport const myCallable = onCall((request) => {\n  if (!request.auth) throw new HttpsError("unauthenticated", "Login required");\n});`,
      });
    }
  }

  // Check Firebase Storage rules — test if unauthenticated reads/writes are allowed via storage.googleapis.com
  if (projectId) {
    const storageBuckets = [
      `${projectId}.appspot.com`,
      `${projectId}.firebasestorage.app`,
    ];

    const storageRuleResults = await Promise.allSettled(
      storageBuckets.flatMap((bucket) => [
        // Test unauthenticated read via storage.googleapis.com
        scanFetch(`https://storage.googleapis.com/v0/b/${bucket}/o?maxResults=3`).then(async (res) => {
          if (!res.ok) return null;
          const data = await res.json() as { items?: { name: string }[] };
          if (data.items && data.items.length > 0) return { bucket, type: "read" as const, files: data.items.map((i) => i.name) };
          return null;
        }).catch(() => null),
        // Test unauthenticated write via storage.googleapis.com
        scanFetch(`https://storage.googleapis.com/upload/storage/v1/b/${bucket}/o?uploadType=media&name=_vibeshield_test.txt`, {
          method: "POST",
          headers: { "Content-Type": "text/plain" },
          body: "vibeshield-test",
          timeoutMs: 8000,
        }).then(async (res) => {
          if (res.ok) {
            scanFetch(`https://storage.googleapis.com/storage/v1/b/${bucket}/o/_vibeshield_test.txt`, { method: "DELETE" }).catch(() => {});
            return { bucket, type: "write" as const };
          }
          return null;
        }).catch(() => null),
      ]),
    );

    for (const r of storageRuleResults) {
      if (r.status !== "fulfilled" || !r.value) continue;
      const v = r.value;
      if (v.type === "read") {
        findings.push({
          id: `firebase-storage-rules-read-${v.bucket}`, module: "Firebase", severity: "high",
          title: `Firebase Storage bucket "${v.bucket}" allows unauthenticated reads`,
          description: `The storage.googleapis.com endpoint confirms unauthenticated read access to bucket "${v.bucket}". Found files: ${v.files.slice(0, 3).join(", ")}${v.files.length > 3 ? "..." : ""}`,
          evidence: `GET storage.googleapis.com/v0/b/${v.bucket}/o → 200 OK\nFiles: ${v.files.join(", ")}`,
          remediation: "Update Firebase Storage rules to require authentication for read access.",
          cwe: "CWE-862", owasp: "A01:2021",
          codeSnippet: `// storage.rules\nrules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n    match /{allPaths=**} {\n      allow read: if request.auth != null;\n    }\n  }\n}`,
        });
      }
      if (v.type === "write") {
        findings.push({
          id: `firebase-storage-rules-write-${v.bucket}`, module: "Firebase", severity: "critical",
          title: `Firebase Storage bucket "${v.bucket}" allows unauthenticated writes`,
          description: `The storage.googleapis.com upload endpoint accepted an unauthenticated file upload to bucket "${v.bucket}". Attackers can upload arbitrary files.`,
          evidence: `POST storage.googleapis.com/upload/storage/v1/b/${v.bucket}/o → 200 OK`,
          remediation: "Update Firebase Storage rules to require authentication for write access.",
          cwe: "CWE-862", owasp: "A01:2021",
          codeSnippet: `// storage.rules\nrules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n    match /{allPaths=**} {\n      allow write: if request.auth != null\n        && request.resource.size < 5 * 1024 * 1024;\n    }\n  }\n}`,
        });
      }
    }
  }

  // Check Firebase Auth email enumeration via fetchSignInMethodsForEmail
  if (apiKey) {
    const emailEnumResult = await scanFetch(`https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${apiKey}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: ["nonexistent-vibeshield-test@example.com"] }),
    }).then(async (res) => {
      if (!res.ok) return null;
      const data = await res.json() as { users?: unknown[] };
      // If the endpoint responds with structured data (even empty users), it's accessible
      if (typeof data === "object" && data !== null) return true;
      return null;
    }).catch(() => null);

    if (emailEnumResult) {
      findings.push({
        id: "firebase-auth-lookup-exposed", module: "Firebase", severity: "medium",
        title: "Firebase Auth accounts:lookup endpoint is accessible",
        description: "The accounts:lookup endpoint is accessible with the API key, allowing attackers to check user details. Combined with createAuthUri, this enables full email enumeration.",
        evidence: `POST identitytoolkit.googleapis.com/v1/accounts:lookup?key=${apiKey} → 200 OK`,
        remediation: "Enable Email Enumeration Protection in Firebase Console → Authentication → Settings. Restrict API key usage to specific domains.",
        cwe: "CWE-204", owasp: "A07:2021",
        codeSnippet: `// Firebase Console → Authentication → Settings\n// Enable "Email Enumeration Protection"\n\n// Also restrict API key in GCP Console:\n// APIs & Services → Credentials → Edit API key\n// Add HTTP referrer restrictions`,
      });
    }
  }

  // Check Firebase Remote Config / init.json exposure
  if (projectId) {
    const remoteConfigPaths = [
      `https://${projectId}.firebaseapp.com/__/firebase/init.json`,
      `https://${projectId}.web.app/__/firebase/init.json`,
      `https://${projectId}.firebaseapp.com/firebase-config.json`,
      `https://${projectId}.web.app/firebase-config.json`,
    ];

    const remoteConfigResults = await Promise.allSettled(
      remoteConfigPaths.map(async (url) => {
        const res = await scanFetch(url, { timeoutMs: 5000 });
        if (!res.ok) return null;
        const text = await res.text();
        try {
          const data = JSON.parse(text) as Record<string, unknown>;
          if (data.projectId || data.apiKey || data.messagingSenderId) {
            return { url, keys: Object.keys(data) };
          }
        } catch { /* not JSON */ }
        return null;
      }),
    );

    for (const r of remoteConfigResults) {
      if (r.status !== "fulfilled" || !r.value) continue;
      const v = r.value;
      findings.push({
        id: "firebase-remote-config-exposed", module: "Firebase", severity: "medium",
        title: "Firebase configuration JSON is publicly accessible",
        description: `The Firebase init/config JSON at ${v.url} exposes project configuration including: ${v.keys.join(", ")}. While Firebase API keys are designed to be public, this reveals the full project configuration that can be used to enumerate other attack surfaces.`,
        evidence: `GET ${v.url} → 200 OK\nExposed keys: ${v.keys.join(", ")}`,
        remediation: "Restrict API key usage in GCP Console. Apply domain restrictions. Ensure no sensitive configuration (server keys, secrets) is included in the config.",
        cwe: "CWE-200", owasp: "A01:2021",
        codeSnippet: `// Restrict API key in GCP Console:\n// APIs & Services → Credentials → Edit key\n// Application restrictions → HTTP referrers\n// API restrictions → Only allow required APIs`,
      });
      break;
    }
  }

  // Check Firebase Cloud Messaging (FCM) server key exposure in client-side code
  const fcmServerKeyPattern = /["'](?:key|serverKey|server_key|fcm_server_key|AAAA[A-Za-z0-9_-]{7,}:APA91b[A-Za-z0-9_-]+)["']/g;
  const fcmKeyMatch = allJs.match(fcmServerKeyPattern);
  const fcmLegacyKeyPattern = /AAAA[A-Za-z0-9_-]{7,}:APA91b[A-Za-z0-9_-]+/;
  const fcmLegacyMatch = allJs.match(fcmLegacyKeyPattern);

  if (fcmLegacyMatch) {
    findings.push({
      id: "firebase-fcm-server-key-exposed", module: "Firebase", severity: "high",
      title: "Firebase Cloud Messaging server key exposed in client code",
      description: "An FCM server key was found in client-side JavaScript. This key allows anyone to send push notifications to your app's users, potentially for phishing, spam, or social engineering attacks.",
      evidence: `Found FCM server key pattern: ${fcmLegacyMatch[0].substring(0, 20)}...${fcmLegacyMatch[0].substring(fcmLegacyMatch[0].length - 10)}`,
      remediation: "Remove the FCM server key from client code immediately. Use FCM HTTP v1 API with service account credentials on the server side instead of legacy server keys.",
      cwe: "CWE-798", owasp: "A07:2021",
      codeSnippet: `// NEVER embed FCM server key in client code\n// Migrate to FCM HTTP v1 API (server-side only):\nimport { getMessaging } from "firebase-admin/messaging";\n\nconst message = {\n  notification: { title: "Hello", body: "World" },\n  token: userFcmToken,\n};\nawait getMessaging().send(message);`,
    });
  } else if (fcmKeyMatch) {
    const suspiciousKeys = fcmKeyMatch.filter((k) => k.includes("serverKey") || k.includes("server_key") || k.includes("fcm_server_key"));
    if (suspiciousKeys.length > 0) {
      findings.push({
        id: "firebase-fcm-key-reference", module: "Firebase", severity: "medium",
        title: "Possible FCM server key reference in client code",
        description: `Found references to FCM server key variables in client-side JavaScript: ${suspiciousKeys.slice(0, 3).join(", ")}. If these contain actual server keys, attackers can send unauthorized push notifications.`,
        evidence: `Found key references: ${suspiciousKeys.slice(0, 3).join(", ")}`,
        remediation: "Verify these are not actual server keys. Move FCM server key handling to backend code.",
        cwe: "CWE-798", owasp: "A07:2021",
        codeSnippet: `// Use FCM HTTP v1 API on the server instead of legacy keys\nimport { getMessaging } from "firebase-admin/messaging";\nawait getMessaging().send({ token, notification });`,
      });
    }
  }

  // Check for service account key exposure in JS bundles
  const saKeyPatterns = [
    { pattern: /["']type["']\s*:\s*["']service_account["']/i, desc: "service_account JSON type field" },
    { pattern: /["']private_key["']\s*:\s*["']-----BEGIN (?:RSA )?PRIVATE KEY/i, desc: "private_key with PEM header" },
    { pattern: /["']client_email["']\s*:\s*["'][^"']+@[^"']*\.iam\.gserviceaccount\.com["']/i, desc: "IAM service account email" },
  ];

  const saMatches = saKeyPatterns.filter((p) => p.pattern.test(allJs));
  if (saMatches.length >= 2) {
    findings.push({
      id: "firebase-service-account-exposed", module: "Firebase", severity: "critical",
      title: "Firebase/GCP service account key exposed in client code",
      description: `Service account credentials were found in client-side JavaScript (matched: ${saMatches.map((m) => m.desc).join(", ")}). This grants full administrative access to your Firebase project and any GCP services the account has access to.`,
      evidence: `Found ${saMatches.length} service account key indicators in JS bundles`,
      remediation: "Remove the service account key from client code IMMEDIATELY. Rotate the key in GCP Console → IAM → Service Accounts. Service account keys should only exist on the server side, ideally using environment variables or GCP Secret Manager.",
      cwe: "CWE-798", owasp: "A07:2021",
      codeSnippet: `// NEVER embed service account keys in client code\n// Server-side only:\nimport admin from "firebase-admin";\n\n// Option 1: Use Application Default Credentials (recommended)\nadmin.initializeApp();\n\n// Option 2: Use environment variable\nadmin.initializeApp({\n  credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT!)),\n});`,
    });
  }

  if (authConfigResult) {
    if (authConfigResult.signupOpen) {
      findings.push({
        id: "firebase-auth-anonymous-signup", module: "Firebase", severity: "high",
        title: "Firebase Auth allows anonymous account creation",
        description: "Anyone can create new user accounts via the Firebase Auth API without any restrictions. This can be used to create spam accounts or enumerate internal features.",
        evidence: `POST identitytoolkit.googleapis.com/v1/accounts:signUp → created anonymous user`,
        remediation: "Disable anonymous auth if not needed. Add email domain restrictions or CAPTCHA to signup flows.",
        cwe: "CWE-287", owasp: "A07:2021",
        codeSnippet: `// Firebase Console → Authentication → Sign-in method\n// Disable "Anonymous" provider if not needed\n\n// For email signup, add domain restrictions:\nconst allowedDomains = ["yourcompany.com"];\nif (!allowedDomains.some(d => email.endsWith("@" + d))) {\n  throw new Error("Signup restricted to company emails");\n}`,
      });
    }
    if (authConfigResult.emailEnumerable) {
      findings.push({
        id: "firebase-auth-email-enum", module: "Firebase", severity: "medium",
        title: "Firebase Auth leaks email registration status",
        description: `The createAuthUri endpoint reveals whether an email is registered. ${authConfigResult.providers?.length ? `Enabled providers: ${authConfigResult.providers.join(", ")}` : ""} Attackers can enumerate valid accounts.`,
        evidence: `POST identitytoolkit.googleapis.com/v1/accounts:createAuthUri\nReturns "registered" boolean for any email`,
        remediation: "Enable Email Enumeration Protection in Firebase Console → Authentication → Settings.",
        cwe: "CWE-204", owasp: "A07:2021",
        codeSnippet: `// Firebase Console → Authentication → Settings\n// Enable "Email Enumeration Protection"\n// This makes signIn/signUp/resetPassword return\n// the same response regardless of email existence`,
      });
    }
  }

  return findings;
};
