import type { RawGitleaksFinding } from "./gitleaks.js";
import type { ScanFinding, ScanSummary, Severity } from "./types.js";

// Static (no LLM) risk explanation + severity per gitleaks rule ID, for the
// secret types most likely to actually show up and matter in a public repo.
// Anything gitleaks detects that isn't listed here still gets a finding —
// RULE_INFO_FALLBACK below builds one from gitleaks' own rule description,
// just without our added risk framing.
const RULE_INFO: Record<string, { severity: Severity; risk: string }> = {
  "aws-access-token": {
    severity: "critical",
    risk: "Grants direct programmatic access to an AWS account. Depending on the attached IAM policy, this can mean full control of cloud infrastructure, data stores, and billing.",
  },
  "gcp-api-key": {
    severity: "critical",
    risk: "Can allow unauthorized use of Google Cloud services billed to your account, and depending on restrictions, access to project data.",
  },
  "azure-ad-client-secret": {
    severity: "critical",
    risk: "Allows an attacker to authenticate as your application against Azure AD, potentially reaching any resource that app has been granted.",
  },
  "private-key": {
    severity: "critical",
    risk: "A private key (TLS, SSH, or signing) grants whoever holds it the ability to impersonate the service, decrypt traffic, or push code as you.",
  },
  "pkcs12-file": {
    severity: "critical",
    risk: "A PKCS#12 bundle typically contains a private key and certificate together — equivalent to leaking both at once.",
  },
  "kubernetes-secret-yaml": {
    severity: "critical",
    risk: "Kubernetes Secrets often hold database credentials, TLS keys, or service tokens for an entire cluster workload.",
  },
  "vault-service-token": {
    severity: "critical",
    risk: "A HashiCorp Vault service token can unlock every secret that token's policy has access to — often the organization's entire secret store.",
  },
  "stripe-access-token": {
    severity: "critical",
    risk: "A live Stripe key can move real money, issue refunds, and expose customer payment data.",
  },
  "square-access-token": {
    severity: "critical",
    risk: "Can be used to process or refund real payments and access transaction data through Square.",
  },
  "plaid-secret-key": {
    severity: "critical",
    risk: "Grants access to linked bank account data and transactions through Plaid.",
  },
  "flutterwave-secret-key": {
    severity: "critical",
    risk: "Can initiate or manipulate real payment transactions through Flutterwave.",
  },
  "github-pat": {
    severity: "high",
    risk: "A GitHub Personal Access Token can read or write private repositories and, depending on scopes, modify CI/CD, packages, or org settings.",
  },
  "github-fine-grained-pat": {
    severity: "high",
    risk: "A fine-grained GitHub token can still grant meaningful repository or organization access depending on how it was scoped.",
  },
  "github-oauth": {
    severity: "high",
    risk: "Can be used to act as the authorizing user against the GitHub API within its granted scopes.",
  },
  "gitlab-pat": {
    severity: "high",
    risk: "Can read or write GitLab projects and pipelines depending on scope.",
  },
  "npm-access-token": {
    severity: "high",
    risk: "Can be used to publish malicious versions of packages you own to the public npm registry — a supply-chain risk for everyone who depends on them.",
  },
  "pypi-upload-token": {
    severity: "high",
    risk: "Can be used to publish malicious package versions to PyPI under your project's name.",
  },
  "rubygems-api-token": {
    severity: "high",
    risk: "Can be used to publish malicious gem versions under your account.",
  },
  "digitalocean-pat": {
    severity: "high",
    risk: "Grants API control over DigitalOcean infrastructure billed to your account.",
  },
  "digitalocean-access-token": {
    severity: "high",
    risk: "Grants API control over DigitalOcean infrastructure billed to your account.",
  },
  "heroku-api-key": {
    severity: "high",
    risk: "Can be used to manage and access apps, config vars (often including other secrets), and data on Heroku.",
  },
  "cloudflare-api-key": {
    severity: "high",
    risk: "Can modify DNS, redirect traffic, or change security settings for every domain on the Cloudflare account.",
  },
  "cloudflare-global-api-key": {
    severity: "high",
    risk: "A global Cloudflare key has full account access — DNS, security rules, and billing.",
  },
  "openai-api-key": {
    severity: "high",
    risk: "Usage on this key is billed to your account and can be used to exhaust your API quota or budget.",
  },
  "anthropic-api-key": {
    severity: "high",
    risk: "Usage on this key is billed to your account and can be used to exhaust your API quota or budget.",
  },
  "twilio-api-key": {
    severity: "high",
    risk: "Can be used to send SMS/calls billed to your account, or access call/message logs.",
  },
  "sendgrid-api-token": {
    severity: "high",
    risk: "Can be used to send email as you, including phishing sent from a domain your recipients already trust.",
  },
  "planetscale-password": {
    severity: "high",
    risk: "Direct database credentials — can read or write production data depending on the branch/role.",
  },
  "sidekiq-secret": {
    severity: "high",
    risk: "Can grant access to the Sidekiq web dashboard, exposing background job data and internal application details.",
  },
  "jwt": {
    severity: "medium",
    risk: "A JSON Web Token may still be valid and could grant its bearer whatever access it was issued for until it expires.",
  },
  "jwt-base64": {
    severity: "medium",
    risk: "A JSON Web Token may still be valid and could grant its bearer whatever access it was issued for until it expires.",
  },
  "slack-webhook-url": {
    severity: "medium",
    risk: "Can be used to post messages into your Slack workspace, which is commonly abused for phishing internal users.",
  },
  "slack-bot-token": {
    severity: "medium",
    risk: "Can act as your Slack app/bot within its granted scopes — reading or posting messages, depending on permissions.",
  },
  "mailchimp-api-key": {
    severity: "medium",
    risk: "Can access your audience/contact lists and send campaigns as you.",
  },
  "hubspot-api-key": {
    severity: "medium",
    risk: "Can read or modify CRM data (contacts, deals) depending on scopes.",
  },
  "intercom-api-key": {
    severity: "medium",
    risk: "Can read customer conversations and contact data through Intercom.",
  },
  "datadog-access-token": {
    severity: "medium",
    risk: "Can read monitoring data or, depending on scope, modify alerting configuration.",
  },
  "new-relic-user-api-key": {
    severity: "medium",
    risk: "Can read application performance data and account configuration.",
  },
  "sentry-user-token": {
    severity: "medium",
    risk: "Can read error-tracking data, which often itself contains sensitive request details or other leaked secrets.",
  },
  "grafana-api-key": {
    severity: "medium",
    risk: "Can read or modify monitoring dashboards depending on the key's role.",
  },
  "notion-api-token": {
    severity: "medium",
    risk: "Can read or write whatever Notion workspace content the integration was shared with.",
  },
  "linear-api-key": {
    severity: "medium",
    risk: "Can read or modify issues and project data in Linear.",
  },
  "generic-api-key": {
    severity: "low",
    risk: "Gitleaks flagged this as a high-entropy string that looks like a credential, but couldn't identify the specific service. Worth a manual look — it may be a false positive, or a real key for an internal or less-common service.",
  },
  "curl-auth-header": {
    severity: "low",
    risk: "An authorization value hardcoded into a curl command — likely fine if it's a test/throwaway credential, worth checking if it isn't.",
  },
  "curl-auth-user": {
    severity: "low",
    risk: "Basic-auth credentials hardcoded into a curl command.",
  },
  "mailgun-pub-key": {
    severity: "low",
    risk: "This is a public validation key by design — low risk, but confirm it's actually the public one and not paired with a private key nearby.",
  },
  "lob-pub-api-key": {
    severity: "low",
    risk: "This is a publishable key by design — generally low risk on its own.",
  },
};

function fallbackRiskInfo(finding: RawGitleaksFinding): { severity: Severity; risk: string } {
  return {
    severity: "medium",
    risk: finding.Description || "Gitleaks flagged this as a potential secret. Review it manually to confirm whether it's a real, live credential.",
  };
}

// Shows enough of the secret to identify which one it is without ever
// exposing the full value — e.g. "sk_live_51H8****...defg".
export function maskSecret(secret: string): string {
  const value = secret.trim();
  if (value.length <= 12) return "*".repeat(Math.max(value.length, 4));

  const prefixLen = Math.min(8, Math.floor(value.length / 3));
  const suffixLen = 4;
  return `${value.slice(0, prefixLen)}****...${value.slice(-suffixLen)}`;
}

export function buildFindings(raw: RawGitleaksFinding[]): ScanFinding[] {
  return raw.map((f) => {
    const info = RULE_INFO[f.RuleID] ?? fallbackRiskInfo(f);
    return {
      ruleId: f.RuleID,
      description: info.risk,
      severity: info.severity,
      file: f.File,
      line: f.StartLine,
      maskedSecret: maskSecret(f.Secret),
    };
  });
}

export function summarize(findings: ScanFinding[]): ScanSummary {
  const summary: ScanSummary = { total: findings.length, critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) summary[f.severity]++;
  return summary;
}
