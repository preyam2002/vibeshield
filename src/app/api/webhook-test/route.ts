import { NextResponse, type NextRequest } from "next/server";
import { validateApiKey } from "@/lib/auth";

const isPrivateHost = (host: string): boolean => {
  if (host === "localhost" || host === "0.0.0.0" || host === "::1") return true;
  if (host.endsWith(".internal") || host.endsWith(".local") || host.endsWith(".localhost")) return true;
  if (host.startsWith("::ffff:")) return isPrivateHost(host.slice(7));
  if (host.startsWith("fd") || host.startsWith("fe80:") || host.startsWith("fc")) return true;
  const parts = host.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p))) return false;
  const [a, b] = parts;
  if (a === 127 || a === 10 || a === 0) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 169 && b === 254) return true;
  return false;
};

/**
 * Webhook test endpoint — sends a sample payload to a webhook URL
 * so users can verify their Slack/Discord integration works.
 *
 * POST /api/webhook-test
 * Body: { url: string, format: "slack" | "discord" | "json" }
 */
export async function POST(req: NextRequest) {
  const auth = validateApiKey(req);
  if (!auth.valid) return NextResponse.json({ error: auth.error }, { status: 401 });
  let body: { url?: string; format?: string };
  try { body = await req.json(); } catch { return NextResponse.json({ error: "Invalid JSON in request body" }, { status: 400 }); }

  const webhookUrl = typeof body.url === "string" ? body.url.trim() : "";
  if (!webhookUrl) {
    return NextResponse.json({ error: "Webhook URL is required" }, { status: 400 });
  }

  let parsed: URL;
  try {
    parsed = new URL(webhookUrl);
    if (parsed.protocol !== "https:") {
      return NextResponse.json({ error: "Webhook URL must use HTTPS" }, { status: 400 });
    }
  } catch {
    return NextResponse.json({ error: "Invalid URL" }, { status: 400 });
  }

  if (isPrivateHost(parsed.hostname)) {
    return NextResponse.json({ error: "Webhook URL cannot point to private addresses" }, { status: 400 });
  }

  const format = body.format === "discord" ? "discord" : body.format === "json" ? "json" : "slack";

  const samplePayload = (() => {
    if (format === "slack") {
      return {
        blocks: [
          { type: "header", text: { type: "plain_text", text: "VibeShield Webhook Test" } },
          { type: "section", fields: [
            { type: "mrkdwn", text: "*Grade:*\n:large_green_circle: B+ (78/100)" },
            { type: "mrkdwn", text: "*Findings:*\n11 total" },
          ]},
          { type: "section", text: { type: "mrkdwn", text: "*2* high  ·  *5* medium  ·  *3* low  ·  *1* info" } },
          { type: "context", elements: [
            { type: "mrkdwn", text: "This is a test notification from VibeShield. If you see this, your webhook is configured correctly!" },
          ]},
        ],
      };
    }

    if (format === "discord") {
      return {
        embeds: [{
          title: "VibeShield Webhook Test",
          color: 0x22c55e,
          fields: [
            { name: "Grade", value: "B+ (78/100)", inline: true },
            { name: "Findings", value: "11 total", inline: true },
            { name: "Quality Gate", value: "PASS", inline: true },
          ],
          footer: { text: "This is a test notification. Your webhook is configured correctly!" },
          timestamp: new Date().toISOString(),
        }],
      };
    }

    // JSON format
    return {
      tool: "vibeshield",
      event: "webhook_test",
      message: "This is a test notification. Your webhook is configured correctly!",
      sample: {
        grade: "B+",
        score: 78,
        findings: 11,
        summary: { critical: 0, high: 2, medium: 5, low: 3, info: 1 },
      },
    };
  })();

  try {
    const res = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(samplePayload),
      signal: AbortSignal.timeout(10000),
    });

    if (!res.ok) {
      return NextResponse.json({
        success: false,
        status: res.status,
        error: `Webhook returned ${res.status}: ${res.statusText}`,
      });
    }

    return NextResponse.json({ success: true, status: res.status, format });
  } catch (err) {
    return NextResponse.json({
      success: false,
      error: "Failed to send webhook",
    });
  }
}
