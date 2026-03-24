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
    pattern: /re_[a-zA-Z0-9]{20,}/g,
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
  // Supabase URL patterns (info, not secret, but useful context)
  {
    name: "Exposed .env Reference",
    pattern: /process\.env\.[A-Z_]{5,}/g,
    severity: "info",
    description: "References to environment variables found in client bundle. If the build isn't configured correctly, these could be undefined instead of populated.",
    remediation: "Verify these env vars are correctly prefixed (NEXT_PUBLIC_ for Next.js) and don't contain secrets.",
  },
];

// Placeholder/test values that look like secrets but aren't
const PLACEHOLDER_PATTERNS = [
  /^(test|example|placeholder|demo|dummy|fake|mock|sample|your[_-])/i,
  /^(xxx|aaa|123|000|foo|bar|baz|todo|fixme)/i,
  /^(password|secret|token|key|auth)/i,  // Value IS the key name (common in minified code)
  /%/,  // CSS/URL-encoded values
  /\.\.\./,  // Ellipsis/placeholder
  /^[a-z]{1,3}[_-][a-z]{1,3}$/i,  // Very short like "a-key", "au-tok"
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
      const validMatches = unique.slice(0, 3).filter((match) =>
        !(pat.name === "Generic Secret/Password in Code" && isPlaceholderValue(match)),
      );
      for (let i = 0; i < validMatches.length; i++) {
        const match = validMatches[i];
        const redacted = match.length > 20
          ? match.substring(0, 10) + "..." + match.substring(match.length - 5)
          : match.substring(0, 8) + "...";
        const suffix = validMatches.length > 1 ? ` (#${i + 1})` : "";
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
        });
      }
    }
  }

  return findings;
};
