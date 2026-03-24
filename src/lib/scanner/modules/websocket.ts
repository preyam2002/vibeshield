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
      });
    }
  }

  // Check for Socket.IO without auth
  if (/socket\.io/i.test(allJs)) {
    const socketPaths = ["/socket.io/", "/socket.io/socket.io.js"];
    for (const path of socketPaths) {
      try {
        const res = await scanFetch(target.baseUrl + path);
        if (res.ok) {
          findings.push({
            id: `websocket-socketio-exposed-${findings.length}`,
            module: "WebSocket",
            severity: "medium",
            title: "Socket.IO endpoint publicly accessible",
            description: "Socket.IO is accessible without authentication. Attackers may be able to subscribe to real-time events and receive other users' data.",
            evidence: `GET ${target.baseUrl + path} → ${res.status}`,
            remediation: "Add authentication middleware to Socket.IO connections. Verify auth tokens on the 'connection' event.",
            cwe: "CWE-306",
          });
          break;
        }
      } catch {
        // skip
      }
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
    });
  }

  return findings;
};
