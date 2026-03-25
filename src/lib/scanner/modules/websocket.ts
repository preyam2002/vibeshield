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

  // Check for Ably key exposure
  const ablyMatch = allJs.match(/(?:ably|ABLY).*?["']([a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,})["']/i);
  if (ablyMatch) {
    const keyParts = ablyMatch[1].split(".");
    findings.push({
      id: "websocket-ably-key",
      module: "WebSocket",
      severity: keyParts.length > 1 && keyParts[1].length > 10 ? "high" : "info",
      title: keyParts.length > 1 && keyParts[1].length > 10
        ? "Ably API key with secret exposed in client code"
        : "Ably API key found",
      description: keyParts.length > 1 && keyParts[1].length > 10
        ? "A full Ably API key (including the secret) is exposed in client code. This allows publishing to any channel and accessing all channel history."
        : "Ably key is in client code. Ensure only subscribe-only token auth is used client-side.",
      evidence: `Key: ${ablyMatch[1].substring(0, 10)}...`,
      remediation: "Use Ably token auth on the client. Generate tokens server-side with restricted capabilities (subscribe only).",
      cwe: "CWE-798",
      codeSnippet: `// Server-side token generation\nconst ably = new Ably.Rest(process.env.ABLY_API_KEY!);\nexport async function POST(req: Request) {\n  const session = await auth();\n  if (!session) return Response.json({ error: "Unauthorized" }, { status: 401 });\n  const tokenRequest = await ably.auth.createTokenRequest({\n    capability: { "public:*": ["subscribe"] }, // subscribe only\n  });\n  return Response.json(tokenRequest);\n}`,
    });
  }

  // Check for Supabase Realtime or LiveBlocks keys
  const liveblocksMatch = allJs.match(/pk_(?:live|test)_[a-zA-Z0-9_-]{20,}/);
  if (liveblocksMatch) {
    findings.push({
      id: "websocket-liveblocks-key",
      module: "WebSocket",
      severity: "info",
      title: "Liveblocks public key found",
      description: "Liveblocks public key is in client code (expected). Ensure room-level auth is configured to prevent unauthorized access.",
      evidence: `Key: ${liveblocksMatch[0].substring(0, 12)}...`,
      remediation: "Configure Liveblocks room authorization in your /api/liveblocks-auth endpoint to restrict access.",
      codeSnippet: `// app/api/liveblocks-auth/route.ts\nimport { Liveblocks } from "@liveblocks/node";\nconst liveblocks = new Liveblocks({ secret: process.env.LIVEBLOCKS_SECRET_KEY! });\nexport async function POST(req: Request) {\n  const user = await getUser(req);\n  if (!user) return Response.json({ error: "Unauthorized" }, { status: 401 });\n  const session = liveblocks.prepareSession(user.id);\n  session.allow("room:*", session.READ_ACCESS); // restrict as needed\n  const { body, status } = await session.authorize();\n  return new Response(body, { status });\n}`,
    });
  }

  // Check for PartyKit/Partyserver patterns (common in vibe-coded apps)
  const partyMatch = allJs.match(/partykit\.dev|partysocket|PartySocket|partykit\.ai/i);
  if (partyMatch) {
    const partyUrlMatch = allJs.match(/["'](https?:\/\/[^"']*\.partykit\.dev[^"']*)["']/);
    if (partyUrlMatch) {
      // Test if the party server is accessible without auth
      try {
        const res = await scanFetch(partyUrlMatch[1], { timeoutMs: 5000 });
        if (res.ok || res.status === 426) {
          findings.push({
            id: "websocket-partykit-open",
            module: "WebSocket",
            severity: "medium",
            title: "PartyKit server accessible without authentication",
            description: "The PartyKit real-time server is accessible. Verify that room-level authentication is configured to prevent unauthorized access to collaboration sessions.",
            evidence: `PartyKit URL: ${partyUrlMatch[1]}\nStatus: ${res.status}`,
            remediation: "Implement onConnect authentication in your PartyKit server to validate user tokens before allowing connections.",
            cwe: "CWE-306",
            codeSnippet: `// party/main.ts — authenticate connections\nimport type { Party, Connection } from "partykit/server";\nexport default {\n  async onConnect(conn: Connection, room: Party) {\n    const token = new URL(conn.uri, "http://x").searchParams.get("token");\n    if (!token || !await verifyToken(token)) {\n      conn.close(4001, "Unauthorized");\n      return;\n    }\n  },\n};`,
          });
        }
      } catch { /* skip */ }
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

  // Check for WS message handler without input validation
  const dangerousHandlers = [
    { re: /\.onmessage\s*=\s*(?:function|\()\s*[^)]*\)\s*(?:=>)?\s*\{[^}]*(?:eval|innerHTML|document\.write|Function\()/i, vuln: "eval/innerHTML in message handler" },
    { re: /\.onmessage\s*=\s*(?:function|\()\s*[^)]*\)\s*(?:=>)?\s*\{[^}]*JSON\.parse[^}]*(?!try)/i, vuln: "JSON.parse without try/catch" },
  ];
  for (const { re, vuln } of dangerousHandlers) {
    if (re.test(allJs)) {
      findings.push({
        id: `websocket-unsafe-handler-${findings.length}`,
        module: "WebSocket",
        severity: "high",
        title: `Unsafe WebSocket message handler: ${vuln}`,
        description: `A WebSocket message handler uses ${vuln}. Since WebSocket messages can be injected or tampered with (especially without origin validation), processing them with dangerous functions like eval or innerHTML enables XSS via WebSocket.`,
        evidence: `Pattern detected: ${vuln}`,
        remediation: "Never use eval, innerHTML, or document.write with WebSocket message data. Always validate and sanitize incoming messages. Use try/catch around JSON.parse.",
        cwe: "CWE-79",
        owasp: "A03:2021",
        confidence: 65,
        codeSnippet: `// Safe WebSocket message handling\nsocket.onmessage = (event) => {\n  let data;\n  try {\n    data = JSON.parse(event.data);\n  } catch {\n    console.error("Invalid message");\n    return;\n  }\n  // Validate the message schema\n  if (typeof data.type !== "string") return;\n  // Use textContent instead of innerHTML\n  element.textContent = data.text;\n};`,
      });
      break;
    }
  }

  // Check for reconnection without re-authentication
  const hasReconnect = /reconnect|auto.?connect|retry.?connect/i.test(allJs);
  const hasWsAuth = /(?:token|auth|jwt|bearer|session)[^}]*(?:websocket|socket|ws)/i.test(allJs) || /(?:websocket|socket|ws)[^}]*(?:token|auth|jwt|bearer|session)/i.test(allJs);
  if (hasReconnect && !hasWsAuth && hasWsCode) {
    findings.push({
      id: "websocket-reconnect-no-auth",
      module: "WebSocket",
      severity: "low",
      title: "WebSocket auto-reconnect may skip authentication",
      description: "The app has WebSocket reconnection logic but no apparent token/auth handling in the WebSocket setup. If the session expires between disconnection and reconnection, the reconnected socket may operate without valid authentication.",
      evidence: "Reconnection patterns detected but no auth token pattern found in WebSocket code",
      remediation: "Re-authenticate on every WebSocket reconnection. Send a fresh auth token during the handshake or as the first message after reconnecting.",
      cwe: "CWE-306",
      confidence: 45,
    });
  }

  return findings;
};
