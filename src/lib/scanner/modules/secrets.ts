import type { ScanModule, Finding } from "../types";

interface SecretPattern {
  name: string;
  pattern: RegExp;
  severity: Finding["severity"];
  description: string;
  remediation: string;
}

const SECRET_PATTERNS: SecretPattern[] = [
  // AWS
  {
    name: "AWS Access Key",
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: "critical",
    description: "AWS access key found in client-side code. Attackers can use this to access your AWS resources, spin up crypto miners, or steal data.",
    remediation: "Immediately rotate this key in AWS IAM. Move it to server-side environment variables.",
  },
  {
    name: "AWS Secret Key",
    pattern: /(?:aws_secret|AWS_SECRET|secret_access_key)[\s"':=]+([A-Za-z0-9/+=]{40})/g,
    severity: "critical",
    description: "AWS secret access key exposed in client code.",
    remediation: "Rotate immediately. Never ship AWS secrets to the browser.",
  },
  // Stripe
  {
    name: "Stripe Secret Key",
    pattern: /sk_live_[a-zA-Z0-9]{20,}/g,
    severity: "critical",
    description: "Stripe live SECRET key in client-side code. Attackers can create charges, issue refunds, and access all your customer payment data.",
    remediation: "Rotate this key immediately in the Stripe dashboard. Secret keys must NEVER be in client code.",
  },
  {
    name: "Stripe Test Secret Key",
    pattern: /sk_test_[a-zA-Z0-9]{20,}/g,
    severity: "high",
    description: "Stripe test secret key exposed. While this can't process real payments, it reveals your integration patterns and test data.",
    remediation: "Move to server-side environment variables.",
  },
  // Supabase
  {
    name: "Supabase Service Role Key",
    pattern: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}/g,
    severity: "high",
    description: "A JWT token (likely Supabase service role key) was found in client code. The service role key bypasses ALL Row Level Security policies.",
    remediation: "If this is a Supabase service role key, remove it from client code immediately. Only the anon key should be client-side.",
    // Note: validated at match time — we decode the payload and check for "service_role" claim
  },
  // OpenAI
  {
    name: "OpenAI API Key",
    pattern: /sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,}/g,
    severity: "critical",
    description: "OpenAI API key exposed. Attackers can make API calls on your account, potentially racking up thousands in charges.",
    remediation: "Rotate this key in the OpenAI dashboard. Proxy all AI calls through your backend.",
  },
  {
    name: "OpenAI Project Key",
    pattern: /sk-proj-[a-zA-Z0-9_-]{80,}/g,
    severity: "critical",
    description: "OpenAI project API key exposed in client code.",
    remediation: "Rotate immediately. All AI API calls should go through your server.",
  },
  // Anthropic
  {
    name: "Anthropic API Key",
    pattern: /sk-ant-[a-zA-Z0-9_-]{80,}/g,
    severity: "critical",
    description: "Anthropic API key exposed. Attackers can make API calls billed to your account.",
    remediation: "Rotate in the Anthropic console. Proxy through your backend.",
  },
  // Google
  {
    name: "Google API Key",
    pattern: /AIza[0-9A-Za-z_-]{35}/g,
    severity: "high",
    description: "Google API key found in client code. Depending on the key's permissions, attackers may abuse various Google Cloud services.",
    remediation: "Restrict this key's allowed referrers/IPs in the Google Cloud console. Consider moving sensitive operations server-side.",
  },
  // Firebase (private key)
  {
    name: "Firebase Private Key",
    pattern: /-----BEGIN (RSA )?PRIVATE KEY-----/g,
    severity: "critical",
    description: "A private key was found in client-side code. This grants full administrative access.",
    remediation: "Remove immediately. Private keys must never be in client code.",
  },
  // Generic tokens
  {
    name: "GitHub Token",
    pattern: /gh[ps]_[a-zA-Z0-9]{36,}/g,
    severity: "critical",
    description: "GitHub personal access token found. Attackers can access your repositories, create commits, and modify code.",
    remediation: "Revoke this token on GitHub immediately.",
  },
  {
    name: "Slack Token",
    pattern: /xox[bpras]-[a-zA-Z0-9-]{10,}/g,
    severity: "high",
    description: "Slack token found. Attackers can read messages and impersonate your bot.",
    remediation: "Revoke this token in Slack settings.",
  },
  {
    name: "SendGrid API Key",
    pattern: /SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/g,
    severity: "high",
    description: "SendGrid API key exposed. Attackers can send emails from your account (phishing, spam).",
    remediation: "Rotate in SendGrid. Move to server-side.",
  },
  {
    name: "Twilio Auth Token",
    pattern: /(?:twilio|TWILIO).*?([a-f0-9]{32})/g,
    severity: "high",
    description: "Twilio credentials found. Attackers can send SMS, make calls on your account.",
    remediation: "Rotate in Twilio console.",
  },
  {
    name: "Resend API Key",
    pattern: /re_[a-zA-Z0-9]{30,}/g,
    severity: "high",
    description: "Resend API key exposed. Attackers can send emails from your domain.",
    remediation: "Rotate in Resend dashboard. Move to server-side.",
  },
  {
    name: "Database Connection String",
    pattern: /(?:mongodb\+srv|postgres|mysql|redis):\/\/[^\s"'`]+/g,
    severity: "critical",
    description: "Database connection string with credentials found in client code. Attackers can directly access your database.",
    remediation: "Remove immediately. Database connections must only be made from your server.",
  },
  {
    name: "JWT Secret",
    pattern: /(?:jwt_secret|JWT_SECRET|secret_key|SECRET_KEY)[\s"':=]+["']([^"']{8,})["']/g,
    severity: "critical",
    description: "JWT signing secret exposed. Attackers can forge authentication tokens and impersonate any user.",
    remediation: "Rotate this secret immediately. JWT secrets must be server-side only.",
  },
  {
    name: "Generic Secret/Password in Code",
    pattern: /(?:password|passwd|secret|token|api_key|apikey|api-key)[\s]*[=:]\s*["']([^"']{8,})["']/gi,
    severity: "medium",
    description: "A hardcoded secret or password was found in client-side JavaScript.",
    remediation: "Move all secrets to server-side environment variables.",
  },
  // Sentry DSN (often contains auth token)
  {
    name: "Sentry DSN",
    pattern: /https:\/\/[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io\/[0-9]+/g,
    severity: "low",
    description: "Sentry DSN found. While Sentry DSNs are semi-public, attackers can flood your error tracking with fake errors.",
    remediation: "Configure allowed origins in Sentry to prevent abuse.",
  },
  // Modern AI providers
  {
    name: "DeepSeek API Key",
    pattern: /sk-(?!ant-|proj-|live_|test_)[a-f0-9]{48,}/g,
    severity: "critical",
    description: "DeepSeek API key exposed. Attackers can make API calls billed to your account.",
    remediation: "Rotate in the DeepSeek console. Proxy all AI calls through your backend.",
  },
  {
    name: "Groq API Key",
    pattern: /gsk_[a-zA-Z0-9]{48,}/g,
    severity: "critical",
    description: "Groq API key exposed. Attackers can make API calls billed to your account.",
    remediation: "Rotate in the Groq console. Proxy all AI calls through your backend.",
  },
  {
    name: "Hugging Face Token",
    pattern: /hf_[a-zA-Z0-9]{34,}/g,
    severity: "high",
    description: "Hugging Face API token exposed. Attackers can access your models and inference endpoints.",
    remediation: "Rotate in Hugging Face settings. Move to server-side.",
  },
  {
    name: "Replicate API Token",
    pattern: /r8_[a-zA-Z0-9]{36,}/g,
    severity: "critical",
    description: "Replicate API token exposed. Attackers can run models billed to your account.",
    remediation: "Rotate in Replicate settings. Proxy through your backend.",
  },
  {
    name: "Together AI API Key",
    pattern: /tog_[a-zA-Z0-9]{48,}/g,
    severity: "critical",
    description: "Together AI API key exposed. Attackers can make API calls billed to your account.",
    remediation: "Rotate in Together AI dashboard. Proxy through your backend.",
  },
  {
    name: "Fireworks AI API Key",
    pattern: /fw_[a-zA-Z0-9]{36,}/g,
    severity: "critical",
    description: "Fireworks AI API key exposed. Attackers can run models billed to your account.",
    remediation: "Rotate in Fireworks dashboard. Proxy through your backend.",
  },
  // Clerk (auth provider common in vibe-coded apps)
  {
    name: "Clerk Secret Key",
    pattern: /sk_live_[a-zA-Z0-9]{40,}/g,
    severity: "critical",
    description: "Clerk secret key exposed. Attackers can manage users, sessions, and authentication in your app.",
    remediation: "Rotate in Clerk dashboard immediately. Only publishable keys should be client-side.",
  },
  {
    name: "Convex Deploy Key",
    pattern: /prod:[a-z0-9]+:[a-zA-Z0-9]{40,}/g,
    severity: "critical",
    description: "Convex deploy key exposed. Attackers can modify your backend functions and data.",
    remediation: "Rotate in Convex dashboard. Deploy keys must never be in client code.",
  },
  // Mailgun
  {
    name: "Mailgun API Key",
    pattern: /key-[a-f0-9]{32}/g,
    severity: "high",
    description: "Mailgun API key exposed. Attackers can send emails from your domain and access logs.",
    remediation: "Rotate in Mailgun dashboard. Move to server-side.",
  },
  // Mapbox
  {
    name: "Mapbox Secret Token",
    pattern: /sk\.eyJ[a-zA-Z0-9_-]{50,}\.[a-zA-Z0-9_-]{20,}/g,
    severity: "high",
    description: "Mapbox secret access token exposed. Attackers can manage your Mapbox account and rack up usage.",
    remediation: "Rotate in Mapbox. Only public tokens (pk.) should be client-side.",
  },
  // Algolia
  {
    name: "Algolia Admin API Key",
    pattern: /(?:algolia_admin_key|ALGOLIA_ADMIN_KEY|algoliaAdminKey)[\s"':=]+["']([a-f0-9]{32})["']/g,
    severity: "critical",
    description: "Algolia admin API key exposed. Attackers can modify search indices and access all data.",
    remediation: "Rotate in Algolia. Use search-only API keys on the client.",
  },
  // Pinecone
  {
    name: "Pinecone API Key",
    pattern: /pcsk_[a-zA-Z0-9_-]{50,}/g,
    severity: "critical",
    description: "Pinecone API key exposed. Attackers can access and modify your vector database.",
    remediation: "Rotate in Pinecone console. Proxy through your backend.",
  },
  // Datadog
  {
    name: "Datadog API Key",
    pattern: /(?:DD_API_KEY|DATADOG_API_KEY|datadog_api_key)[\s"':=]+["']([a-f0-9]{32})["']/g,
    severity: "high",
    description: "Datadog API key exposed. Attackers can submit metrics and access monitoring data.",
    remediation: "Rotate in Datadog. Use client tokens (pub keys) for RUM.",
  },
  // Linear
  {
    name: "Linear API Key",
    pattern: /lin_api_[a-zA-Z0-9]{40,}/g,
    severity: "high",
    description: "Linear API key exposed. Attackers can access your project management data.",
    remediation: "Rotate in Linear settings. Move to server-side.",
  },
  // Vercel
  {
    name: "Vercel Token",
    pattern: /(?:VERCEL_TOKEN|vercel_token)[\s"':=]+["']([a-zA-Z0-9]{24,})["']/g,
    severity: "high",
    description: "Vercel deployment token exposed. Attackers can deploy to and manage your Vercel projects.",
    remediation: "Rotate in Vercel account settings. Move to server-side.",
  },
  // Upstash
  {
    name: "Upstash Redis Token",
    pattern: /UPSTASH_REDIS_REST_TOKEN[\s"':=]+["']([a-zA-Z0-9_-]{40,})["']/g,
    severity: "high",
    description: "Upstash Redis token exposed. Attackers can read/write your Redis data.",
    remediation: "Rotate in Upstash console. Move to server-side environment variables.",
  },
  // Neon
  {
    name: "Neon Database URL",
    pattern: /postgres(?:ql)?:\/\/[^:]+:[^@]+@[a-z0-9-]+\.neon\.tech\/[^\s"'`]+/g,
    severity: "critical",
    description: "Neon Postgres connection string with credentials exposed. Attackers can directly access your database.",
    remediation: "Rotate the password in Neon console. Database URLs must never be in client code.",
  },
  // Planetscale
  {
    name: "PlanetScale Database URL",
    pattern: /mysql:\/\/[^:]+:[^@]+@[a-z0-9-]+\.connect\.psdb\.cloud\/[^\s"'`]+/g,
    severity: "critical",
    description: "PlanetScale database connection string with credentials exposed.",
    remediation: "Rotate credentials in PlanetScale. Database connections must only be server-side.",
  },
  // Turso
  {
    name: "Turso Database Token",
    pattern: /(?:TURSO_AUTH_TOKEN|turso_auth_token)[\s"':=]+["']([a-zA-Z0-9._-]{40,})["']/g,
    severity: "critical",
    description: "Turso database authentication token exposed. Attackers can access your LibSQL database.",
    remediation: "Rotate in Turso dashboard. Move to server-side.",
  },
  // Lemon Squeezy
  {
    name: "Lemon Squeezy API Key",
    pattern: /(?:LEMONSQUEEZY_API_KEY|LEMON_SQUEEZY_API_KEY)[\s"':=]+["']([a-zA-Z0-9]{30,})["']/g,
    severity: "high",
    description: "Lemon Squeezy API key exposed. Attackers can access your payment and subscription data.",
    remediation: "Rotate in Lemon Squeezy dashboard. Move to server-side.",
  },
  // Resend (already covered but add RESEND_API_KEY env var pattern)
  {
    name: "Postmark Server Token",
    pattern: /(?:POSTMARK_SERVER_TOKEN|postmark.*token)[\s"':=]+["']([a-f0-9-]{36})["']/g,
    severity: "high",
    description: "Postmark server token exposed. Attackers can send emails from your domain.",
    remediation: "Rotate in Postmark. Move to server-side.",
  },
  // Supabase URL with service key in query params
  {
    name: "Supabase Service Key in URL",
    pattern: /supabase\.co\/[^\s]*apikey=eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g,
    severity: "high",
    description: "Supabase API key found embedded in a URL. If this is the service role key, it bypasses all RLS.",
    remediation: "Remove the key from URLs. Use proper header-based authentication.",
  },
  // OpenRouter (popular AI proxy for vibe-coded apps)
  {
    name: "OpenRouter API Key",
    pattern: /sk-or-v1-[a-f0-9]{64}/g,
    severity: "critical",
    description: "OpenRouter API key exposed. Attackers can make API calls to any AI model billed to your account.",
    remediation: "Rotate in OpenRouter dashboard. Proxy all AI calls through your backend.",
  },
  // Mistral AI
  {
    name: "Mistral AI API Key",
    pattern: /(?:MISTRAL_API_KEY|mistral_api_key)[\s"':=]+["']([a-zA-Z0-9]{32,})["']/g,
    severity: "critical",
    description: "Mistral AI API key exposed. Attackers can make inference calls billed to your account.",
    remediation: "Rotate in Mistral console. Proxy through your backend.",
  },
  // ElevenLabs (voice AI)
  {
    name: "ElevenLabs API Key",
    pattern: /(?:ELEVENLABS_API_KEY|elevenlabs.*key|xi-api-key)[\s"':=]+["']([a-f0-9]{32})["']/g,
    severity: "high",
    description: "ElevenLabs API key exposed. Attackers can generate voice clones and audio billed to your account.",
    remediation: "Rotate in ElevenLabs. Move voice API calls to server-side.",
  },
  // Cloudflare
  {
    name: "Cloudflare API Token",
    pattern: /(?:CF_API_TOKEN|CLOUDFLARE_API_TOKEN|cloudflare.*token)[\s"':=]+["']([a-zA-Z0-9_-]{40,})["']/g,
    severity: "critical",
    description: "Cloudflare API token exposed. Attackers can manage your DNS, workers, and security settings.",
    remediation: "Rotate in Cloudflare dashboard. Move to server-side environment variables.",
  },
  // Perplexity
  {
    name: "Perplexity API Key",
    pattern: /pplx-[a-f0-9]{48,}/g,
    severity: "critical",
    description: "Perplexity API key exposed. Attackers can make search/AI calls billed to your account.",
    remediation: "Rotate in Perplexity settings. Proxy through your backend.",
  },
  // Cohere
  {
    name: "Cohere API Key",
    pattern: /(?:COHERE_API_KEY|cohere_api_key)[\s"':=]+["']([a-zA-Z0-9]{40,})["']/g,
    severity: "critical",
    description: "Cohere API key exposed. Attackers can make inference calls billed to your account.",
    remediation: "Rotate in Cohere dashboard. Proxy through your backend.",
  },
  // Supabase (newer patterns)
  {
    name: "Supabase URL with Credentials",
    pattern: /https:\/\/[a-z0-9]+\.supabase\.co\/rest\/v1\/[^\s"'`]*(?:apikey|token)=[a-zA-Z0-9._-]{30,}/g,
    severity: "high",
    description: "Supabase REST API call with embedded credentials found in client code.",
    remediation: "Use the Supabase client library with proper key management instead of raw URLs.",
  },
  // Cursor / Windsurf / Bolt (AI coding tool keys sometimes leak)
  {
    name: "Cursor/Windsurf API Key",
    pattern: /(?:CURSOR_API_KEY|WINDSURF_API_KEY|cursor_api_key)[\s"':=]+["']([a-zA-Z0-9_-]{30,})["']/g,
    severity: "high",
    description: "AI coding tool API key exposed. Attackers can use your account's AI quota.",
    remediation: "Remove from client code. These keys should never be shipped to browsers.",
  },
  // Vercel Blob
  {
    name: "Vercel Blob Token",
    pattern: /vercel_blob_rw_[a-zA-Z0-9]{30,}/g,
    severity: "high",
    description: "Vercel Blob read-write token exposed. Attackers can upload, read, and delete files in your blob store.",
    remediation: "Rotate in Vercel project settings. Use server-side upload handling.",
  },
  // R2/S3 presigned URL patterns (not secret per se, but dangerous if long-lived)
  {
    name: "Long-lived Presigned S3/R2 URL",
    pattern: /https:\/\/[a-z0-9.-]+\.(?:s3|r2)\.(?:amazonaws|cloudflarestorage)\.com\/[^\s"'`]*?(?:X-Amz-Expires|Expires)=(?:8640[0-9]|[1-9]\d{5,})/g,
    severity: "medium",
    description: "A presigned cloud storage URL with a long expiration (>24h) was found in client code. These URLs grant direct access to private objects.",
    remediation: "Use short-lived presigned URLs (1-4 hours max). Generate them on demand via API routes.",
  },
];

// Placeholder/test values that look like secrets but aren't
const PLACEHOLDER_PATTERNS = [
  /^(test|example|placeholder|demo|dummy|fake|mock|sample|your[_-])/i,
  /^(xxx|aaa|123|000|foo|bar|baz|todo|fixme)/i,
  /^(password|passwd|secret|token|key|auth|api[_-]?key|csrf|client)/i,  // Value IS the key name
  /%/,  // CSS/URL-encoded values
  /\.\.\./,  // Ellipsis/placeholder
  /^[a-z]{1,3}[_-][a-z]{1,3}$/i,  // Very short like "a-key", "au-tok"
  /^[a-z_-]+$/i,  // All-alpha values like "required", "enabled", "hidden"
  /^\d+$/,  // Pure numeric like "12345678"
  /^(true|false|null|undefined|none|empty|default|required|enabled|disabled)/i,
];

const isPlaceholderValue = (match: string): boolean => {
  // Extract the value part (after = or :)
  const valueMatch = match.match(/[=:]\s*["']([^"']+)["']/);
  if (!valueMatch) return false;
  const value = valueMatch[1];
  return value.length < 12 || PLACEHOLDER_PATTERNS.some((p) => p.test(value));
};

export const secretsModule: ScanModule = async (target) => {
  const findings: Finding[] = [];
  const allJs = Array.from(target.jsContents.values()).join("\n");

  for (const pat of SECRET_PATTERNS) {
    const matches = allJs.match(pat.pattern);
    if (matches) {
      const unique = [...new Set(matches)];
      const validMatches = unique.slice(0, 3).filter((match) => {
        if (pat.name === "Generic Secret/Password in Code" && isPlaceholderValue(match)) return false;
        // For Supabase JWT pattern, verify it's a service_role key, not an anon key
        if (pat.name === "Supabase Service Role Key") {
          try {
            const payload = match.split(".")[1];
            const decoded = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
            if (decoded.includes('"anon"') && !decoded.includes('"service_role"')) return false;
          } catch { /* proceed with match */ }
        }
        return true;
      });
      for (let i = 0; i < validMatches.length; i++) {
        const match = validMatches[i];
        const redacted = match.length > 20
          ? match.substring(0, 10) + "..." + match.substring(match.length - 5)
          : match.substring(0, 8) + "...";
        const suffix = validMatches.length > 1 ? ` (#${i + 1})` : "";
        const isAiKey = /openai|anthropic|deepseek|groq|replicate|together|fireworks|hugging/i.test(pat.name);
        findings.push({
          id: `secrets-${pat.name.toLowerCase().replace(/\s+/g, "-")}-${findings.length}`,
          module: "Secret Detection",
          severity: pat.severity,
          title: `${pat.name} exposed in client-side JavaScript${suffix}`,
          description: pat.description,
          evidence: `Found: ${redacted}`,
          remediation: pat.remediation,
          cwe: "CWE-798",
          owasp: "A07:2021",
          codeSnippet: isAiKey
            ? `// Move to server-side API route\n// app/api/ai/route.ts\nexport async function POST(req: Request) {\n  const { prompt } = await req.json();\n  const res = await fetch("https://api...", {\n    headers: { Authorization: \`Bearer \${process.env.API_KEY}\` },\n    body: JSON.stringify({ prompt }),\n  });\n  return Response.json(await res.json());\n}`
            : `// Move to .env.local (never commit)\n${pat.name.toUpperCase().replace(/[^A-Z]/g, "_")}=your_key_here\n\n// Access server-side only\nconst key = process.env.${pat.name.toUpperCase().replace(/[^A-Z]/g, "_")};`,
        });
      }
    }
  }

  return findings;
};
