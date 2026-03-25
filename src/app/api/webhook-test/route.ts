import { NextResponse } from "next/server";

/**
 * Webhook test endpoint — sends a sample payload to a webhook URL
 * so users can verify their Slack/Discord integration works.
 *
 * POST /api/webhook-test
 * Body: { url: string, format: "slack" | "discord" | "json" }
 */
export async function POST(req: Request) {
  const body = await req.json() as { url?: string; format?: string };

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
      error: err instanceof Error ? err.message : "Failed to send webhook",
    });
  }
}
