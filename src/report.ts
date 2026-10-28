import { escapeHtml } from "./html.js";
import type { ScanFinding, ScanResult, Severity } from "./types.js";
import { VERSION } from "./version.js";

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

const SEVERITY_STYLE: Record<Severity, { label: string; bg: string; fg: string; border: string }> = {
  critical: { label: "Critical", bg: "#fee2e2", fg: "#991b1b", border: "#dc2626" },
  high: { label: "High", bg: "#ffedd5", fg: "#9a3412", border: "#ea580c" },
  medium: { label: "Medium", bg: "#fef9c3", fg: "#854d0e", border: "#ca8a04" },
  low: { label: "Low", bg: "#f1f5f9", fg: "#475569", border: "#94a3b8" },
};

const RULE_LABEL_ACRONYMS = new Set([
  "aws", "gcp", "api", "jwt", "pat", "npm", "pypi", "oauth", "ci", "cd", "sdk", "url", "ssh", "tls", "yaml", "pkcs12",
]);

const RULE_LABEL_BRANDS: Record<string, string> = { github: "GitHub", gitlab: "GitLab", openai: "OpenAI", sendgrid: "SendGrid" };

export function formatRuleLabel(ruleId: string): string {
  return ruleId
    .split("-")
    .map((word) =>
      RULE_LABEL_BRANDS[word] ?? (RULE_LABEL_ACRONYMS.has(word) ? word.toUpperCase() : word.charAt(0).toUpperCase() + word.slice(1))
    )
    .join(" ");
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString("en-US", {
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZoneName: "short",
  });
}

function statTile(severity: Severity, count: number): string {
  const s = SEVERITY_STYLE[severity];
  return `
    <div class="stat-tile" style="background:${s.bg};border-color:${s.border};">
      <div class="stat-count" style="color:${s.fg};">${count}</div>
      <div class="stat-label" style="color:${s.fg};">${s.label}</div>
    </div>
  `;
}

function severityBadge(severity: Severity): string {
  const s = SEVERITY_STYLE[severity];
  return `<span class="badge" style="background:${s.bg};color:${s.fg};border-color:${s.border};">${s.label}</span>`;
}

function findingsTableRows(findings: ScanFinding[]): string {
  const sorted = [...findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );
  return sorted
    .map(
      (f) => `
        <tr>
          <td>${severityBadge(f.severity)}</td>
          <td>${escapeHtml(formatRuleLabel(f.ruleId))}</td>
          <td class="mono">${escapeHtml(f.file)}</td>
          <td class="mono">${f.line}</td>
          <td class="mono">${escapeHtml(f.maskedSecret)}</td>
        </tr>
      `
    )
    .join("");
}

function riskGlossary(findings: ScanFinding[]): string {
  const seen = new Map<string, ScanFinding>();
  for (const f of findings) if (!seen.has(f.ruleId)) seen.set(f.ruleId, f);

  const entries = [...seen.values()].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );

  return entries
    .map(
      (f) => `
        <div class="glossary-entry">
          <div class="glossary-head">${severityBadge(f.severity)}<span class="glossary-title">${escapeHtml(formatRuleLabel(f.ruleId))}</span></div>
          <p class="glossary-desc">${escapeHtml(f.description)}</p>
        </div>
      `
    )
    .join("");
}

const BRAND_MARK_SVG = `
  <svg width="28" height="28" viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg">
    <rect width="64" height="64" rx="14" fill="#0B1220" />
    <path d="M 20 18 L 34 32 L 20 46" fill="none" stroke="#C9A24B" stroke-width="7" stroke-linecap="round" stroke-linejoin="round" />
    <rect x="40" y="40" width="15" height="6" rx="1.5" fill="#C9A24B" />
  </svg>
`;

// Renders a fully self-contained HTML document (no external stylesheets,
// fonts, scripts, or images — everything inline) so it works both embedded
// in a sandboxed, connect-src:'none' viewer iframe, and when printed to PDF
// via headless Chromium. No LLM involved anywhere — every
// string here is either a static template or escaped scan data.
export function renderReportHtml(result: ScanResult): string {
  const { repoFullName, repoUrl, scanDate, findings, summary } = result;
  const clean = findings.length === 0;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Secret Scan Report — ${escapeHtml(repoFullName)}</title>
<style>
  * { box-sizing: border-box; }
  body {
    margin: 0;
    padding: 40px;
    background: #ffffff;
    color: #0f172a;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    font-size: 14px;
    line-height: 1.55;
  }
  .mono { font-family: "SF Mono", Consolas, "Courier New", monospace; font-size: 12.5px; word-break: break-all; }
  .wrap { max-width: 860px; margin: 0 auto; }
  header.report-header {
    display: flex; align-items: center; justify-content: space-between;
    border-bottom: 2px solid #0B1220; padding-bottom: 16px; margin-bottom: 28px;
  }
  .brand { display: flex; align-items: center; gap: 8px; font-weight: 600; font-size: 13px; letter-spacing: 0.02em; color: #0B1220; }
  .brand .dot { color: #C9A24B; }
  .report-title { text-align: right; }
  .report-title h1 { font-size: 18px; margin: 0; color: #0B1220; }
  .report-title .subtitle { font-size: 12px; color: #64748b; margin-top: 2px; }
  section { margin-bottom: 32px; }
  h2 { font-size: 15px; color: #0B1220; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px; margin: 0 0 16px; }
  .summary-grid { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 8px; }
  .stat-tile { flex: 1; min-width: 110px; border: 1px solid; border-radius: 8px; padding: 14px; text-align: center; }
  .stat-count { font-size: 26px; font-weight: 700; line-height: 1; }
  .stat-label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; margin-top: 6px; }
  .summary-meta { font-size: 13px; color: #334155; margin-top: 12px; }
  .summary-meta strong { color: #0f172a; }
  .clean-banner {
    border: 1px solid #86efac; background: #f0fdf4; color: #166534;
    border-radius: 8px; padding: 16px 18px; font-size: 14px;
  }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  thead { display: table-header-group; }
  th { text-align: left; font-size: 11px; text-transform: uppercase; letter-spacing: 0.03em; color: #64748b; padding: 8px 10px; border-bottom: 1px solid #cbd5e1; }
  td { padding: 9px 10px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
  .badge {
    display: inline-block; border: 1px solid; border-radius: 999px;
    padding: 2px 9px; font-size: 11px; font-weight: 600; white-space: nowrap;
  }
  .glossary-entry { margin-bottom: 14px; }
  .glossary-head { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
  .glossary-title { font-weight: 600; font-size: 13.5px; color: #0f172a; }
  .glossary-desc { margin: 0; color: #334155; font-size: 13px; }
  footer.report-footer {
    border-top: 2px solid #0B1220; padding-top: 16px; margin-top: 40px;
    font-size: 12.5px; color: #475569;
  }
  footer.report-footer a { color: #0B1220; font-weight: 600; }
  @media print {
    body { padding: 0; }
    section, .glossary-entry, tr { break-inside: avoid; page-break-inside: avoid; }
    thead { display: table-header-group; }
  }
</style>
</head>
<body>
  <div class="wrap">
    <header class="report-header">
      <div class="brand">${BRAND_MARK_SVG} MARCAL<span class="dot">&middot;</span>SECURITY</div>
      <div class="report-title">
        <h1>Secret Scan Report</h1>
        <div class="subtitle">${escapeHtml(repoFullName)}</div>
      </div>
    </header>

    <section>
      <h2>Executive Summary</h2>
      <div class="summary-grid">
        ${statTile("critical", summary.critical)}
        ${statTile("high", summary.high)}
        ${statTile("medium", summary.medium)}
        ${statTile("low", summary.low)}
      </div>
      <p class="summary-meta">
        Repository: <strong>${escapeHtml(repoUrl)}</strong><br />
        Scanned: <strong>${escapeHtml(formatDate(scanDate))}</strong><br />
        Total findings: <strong>${summary.total}</strong>
      </p>
    </section>

    ${
      clean
        ? `<section><div class="clean-banner">No exposed secrets or API keys were detected. This scan checks the current file contents — it doesn't cover git history, other branches, or runtime configuration.</div></section>`
        : `
    <section>
      <h2>Findings</h2>
      <table>
        <thead>
          <tr><th>Severity</th><th>Type</th><th>File</th><th>Line</th><th>Value</th></tr>
        </thead>
        <tbody>
          ${findingsTableRows(findings)}
        </tbody>
      </table>
    </section>

    <section>
      <h2>What These Risks Mean</h2>
      ${riskGlossary(findings)}
    </section>
    `
    }

    <footer class="report-footer">
      This automated scan is a starting point, not a substitute for a manual security review — it only checks for
      known secret patterns in the current file contents. <strong>Marcal Security</strong> offers manual, hands-on
      penetration testing that goes further: authorization flaws, business logic issues, and anything a pattern
      scanner can't see. <a href="mailto:sebastian@marcalsecurity.com">Get in touch</a> for a full assessment.
      <br /><br />Generated by marcal-scan v${VERSION} &middot; github.com/MrDavidson23/marcal-scan
    </footer>
  </div>
</body>
</html>`;
}
