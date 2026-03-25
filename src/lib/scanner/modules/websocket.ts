import type { ScanModule, Finding } from "../types";
import { scanFetch } from "../fetch";

export const websocketModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const allJs = Array.from(target.jsContents.values()).join("\n");

  // Detect WebSocket usage
  const wsMatches = allJs.match(/wss?:\/\/[^\s"'`]+/g);
  const hasWsCode = /new\s+WebSocket|\.onmessage|socket\.io|\.connect\(/i.test(allJs);

  if (!wsMatches && !hasWsCode) return findings;

  // Check if WS endpoints use WSS (encrypted)
  if (wsMatches) {
    const insecureWs = wsMatches.filter((u) => u.startsWith("ws://"));
    if (insecureWs.length > 0) {
      findings.push({
        id: "websocket-no-tls",
        module: "WebSocket",
        severity: "high",
        title: "Unencrypted WebSocket connections (ws://)",
        description: "WebSocket connections use ws:// instead of wss://. All real-time data is sent unencrypted.",
        evidence: `Insecure WS URLs: ${insecureWs.slice(0, 3).join(", ")}`,
        remediation: "Use wss:// (WebSocket Secure) for all WebSocket connections.",
        cwe: "CWE-319",
        codeSnippet: `// Always use wss:// in production\nconst wsUrl = process.env.NODE_ENV === "production"\n  ? \`wss://\${window.location.host}/ws\`\n  : \`ws://localhost:3000/ws\`;\nconst socket = new WebSocket(wsUrl);`,
      });
    }
  }

  // Check for Socket.IO without auth — paths in parallel
  if (/socket\.io/i.test(allJs)) {
    const socketResults = await Promise.allSettled(
      ["/socket.io/", "/socket.io/socket.io.js"].map(async (path) => {
        const res = await scanFetch(target.baseUrl + path);
        return res.ok ? { path, status: res.status } : null;
      }),
    );
    for (const r of socketResults) {
      if (r.status !== "fulfilled" || !r.value) continue;
      findings.push({
        id: `websocket-socketio-exposed-${findings.length}`, module: "WebSocket", severity: "medium",
        title: "Socket.IO endpoint publicly accessible",
        description: "Socket.IO is accessible without authentication.",
        evidence: `GET ${target.baseUrl + r.value.path} → ${r.value.status}`,
        remediation: "Add authentication middleware to Socket.IO connections.",
        cwe: "CWE-306",
        codeSnippet: `// Socket.IO — require auth on connection\nio.use((socket, next) => {\n  const token = socket.handshake.auth.token;\n  try {\n    const user = verifyJWT(token);\n    socket.data.user = user;\n    next();\n  } catch {\n    next(new Error("Unauthorized"));\n  }\n});`,
      });
      break;
    }
  }

  // Check for Pusher/Ably keys (common in vibe-coded real-time apps)
  const pusherMatch = allJs.match(/(?:pusher|PUSHER).*?key.*?["']([a-f0-9]{20,})["']/i);
  if (pusherMatch) {
    findings.push({
      id: "websocket-pusher-key",
      module: "WebSocket",
      severity: "info",
      title: "Pusher app key found",
      description: "Pusher key is in client code (this is expected). Ensure private channels require authentication.",
      evidence: `Key: ${pusherMatch[1].substring(0, 8)}...`,
      remediation: "Use private/presence channels for sensitive data. Implement server-side auth for channel subscriptions.",
      codeSnippet: `// Server-side Pusher auth endpoint\napp.post("/pusher/auth", async (req, res) => {\n  const user = await getAuthUser(req);\n  if (!user) return res.status(403).send("Forbidden");\n  const auth = pusher.authorizeChannel(req.body.socket_id, req.body.channel_name);\n  res.send(auth);\n});`,
    });
  }

  // Check for common WebSocket/Socket.IO namespaces
  if (/socket\.io/i.test(allJs) || hasWsCode) {
    const namespaces = ["/admin", "/dashboard", "/internal", "/debug", "/metrics", "/graphql", "/notifications", "/chat"];
    const nsResults = await Promise.allSettled(
      namespaces.map(async (ns) => {
        const res = await scanFetch(`${target.baseUrl}/socket.io/?EIO=4&transport=polling&namespace=${encodeURIComponent(ns)}`, { timeoutMs: 5000 });
        if (res.ok) {
          const text = await res.text();
          if (text.length > 5 && !text.includes("Invalid namespace")) return { ns, status: res.status };
        }
        return null;
      }),
    );
    const foundNs: string[] = [];
    for (const r of nsResults) {
      if (r.status === "fulfilled" && r.value) foundNs.push(r.value.ns);
    }
    if (foundNs.length > 0) {
      findings.push({
        id: "websocket-hidden-namespaces",
        module: "WebSocket",
        severity: foundNs.some((n) => /admin|internal|debug/.test(n)) ? "high" : "medium",
        title: `${foundNs.length} hidden Socket.IO namespace${foundNs.length > 1 ? "s" : ""} accessible`,
        description: `Found accessible Socket.IO namespaces: ${foundNs.join(", ")}. These may expose admin functionality or internal data without authentication.`,
        evidence: `Accessible namespaces:\n${foundNs.map((n) => `  ${n} → 200 OK`).join("\n")}`,
        remediation: "Add authentication middleware to all Socket.IO namespaces, especially admin and internal ones.",
        cwe: "CWE-306",
        owasp: "A01:2021",
        codeSnippet: `// Protect all namespaces\nconst adminNs = io.of("/admin");\nadminNs.use((socket, next) => {\n  const token = socket.handshake.auth.token;\n  if (!verifyAdmin(token)) return next(new Error("Unauthorized"));\n  next();\n});`,
      });
    }
  }

  // Test WebSocket upgrade without auth on discovered WS URLs
  if (wsMatches) {
    const wsUrls = [...new Set(wsMatches)].slice(0, 3);
    const upgradeResults = await Promise.allSettled(
      wsUrls.map(async (wsUrl) => {
        const httpUrl = wsUrl.replace(/^ws(s?):\/\//, "http$1://");
        const res = await scanFetch(httpUrl, {
          headers: {
            Upgrade: "websocket",
            Connection: "Upgrade",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version": "13",
          },
          timeoutMs: 5000,
        });
        return { wsUrl, status: res.status, upgrade: res.headers.get("upgrade") };
      }),
    );
    for (const r of upgradeResults) {
      if (r.status !== "fulfilled") continue;
      const v = r.value;
      if (v.status === 101 || v.upgrade?.toLowerCase() === "websocket") {
        findings.push({
          id: `websocket-no-auth-${findings.length}`, module: "WebSocket", severity: "high",
          title: `WebSocket accepts unauthenticated connections`,
          description: `The WebSocket endpoint ${v.wsUrl} accepts upgrade requests without authentication tokens. Anyone can connect and receive real-time data.`,
          evidence: `Upgrade request to ${v.wsUrl}\nStatus: ${v.status}\nUpgrade header: ${v.upgrade}`,
          remediation: "Require authentication tokens in the WebSocket handshake (query param or cookie).",
          cwe: "CWE-306", owasp: "A07:2021",
          codeSnippet: `// Verify auth during WebSocket upgrade\nconst wss = new WebSocketServer({ noServer: true });\nserver.on("upgrade", (req, socket, head) => {\n  const token = new URL(req.url, "http://x").searchParams.get("token");\n  if (!verifyJWT(token)) { socket.destroy(); return; }\n  wss.handleUpgrade(req, socket, head, (ws) => wss.emit("connection", ws, req));\n});`,
        });
        break;
      }
    }
  }

  // Cross-Site WebSocket Hijacking: test if WS upgrade works with a foreign origin
  if (wsMatches) {
    const wsUrls = [...new Set(wsMatches)].slice(0, 2);
    const cswhResults = await Promise.allSettled(
      wsUrls.map(async (wsUrl) => {
        const httpUrl = wsUrl.replace(/^ws(s?):\/\//, "http$1://");
        const res = await scanFetch(httpUrl, {
          headers: {
            Upgrade: "websocket",
            Connection: "Upgrade",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            "Sec-WebSocket-Version": "13",
            Origin: "https://evil-attacker.com",
          },
          timeoutMs: 5000,
        });
        return { wsUrl, status: res.status, upgrade: res.headers.get("upgrade") };
      }),
    );
    for (const r of cswhResults) {
      if (r.status !== "fulfilled") continue;
      const v = r.value;
      if (v.status === 101 || v.upgrade?.toLowerCase() === "websocket") {
        findings.push({
          id: "websocket-cswsh",
          module: "WebSocket",
          severity: "high",
          title: "Cross-Site WebSocket Hijacking (CSWSH)",
          description: `The WebSocket endpoint ${v.wsUrl} accepts upgrade requests from any Origin. An attacker's website can establish a WebSocket connection to your server using the victim's cookies, enabling real-time data theft.`,
          evidence: `Origin: https://evil-attacker.com\nUpgrade response: ${v.status} (accepted)`,
          remediation: "Validate the Origin header during WebSocket handshake. Only accept connections from your own domain.",
          cwe: "CWE-346",
          owasp: "A07:2021",
          codeSnippet: `// Validate origin during WebSocket upgrade\nconst wss = new WebSocketServer({ noServer: true });\nconst ALLOWED_ORIGINS = ["https://yourdomain.com"];\nserver.on("upgrade", (req, socket, head) => {\n  const origin = req.headers.origin || "";\n  if (!ALLOWED_ORIGINS.includes(origin)) {\n    socket.write("HTTP/1.1 403 Forbidden\\r\\n\\r\\n");\n    socket.destroy();\n    return;\n  }\n  wss.handleUpgrade(req, socket, head, (ws) => wss.emit("connection", ws, req));\n});`,
        });
        break;
      }
    }
  }

  return findings;
};
