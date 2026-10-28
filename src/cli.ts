#!/usr/bin/env node
import { writeFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { parseGithubUrl } from "./github.js";
import { renderReportHtml, formatRuleLabel } from "./report.js";
import { scanDirectory, scanRepo } from "./scan.js";
import { toSarif } from "./sarif.js";
import type { ScanResult, Severity } from "./types.js";
import { VERSION } from "./version.js";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

const HELP = `marcal-scan ${VERSION} — find exposed secrets and API keys

Usage:
  marcal-scan <github-url | directory> [options]

Examples:
  marcal-scan https://github.com/owner/repo
  marcal-scan . --fail-on high --sarif results.sarif
  marcal-scan ./my-app --html report.html

Options:
  --format <pretty|json|sarif>   Output on stdout (default: pretty)
  --html <file>                  Also write a standalone HTML report
  --pdf <file>                   Also write a PDF report (needs puppeteer)
  --sarif <file>                 Also write SARIF for GitHub code scanning
  --fail-on <severity|none>      Exit 1 if any finding is at or above this
                                 severity: critical, high, medium, low (default: none)
  -h, --help                     Show this help
  -v, --version                  Show the version

Environment:
  GITLEAKS_BIN   Path to the gitleaks binary (default: gitleaks on PATH)
  GITHUB_TOKEN   Raises GitHub API rate limits for remote scans
  NO_COLOR       Disable colored output

Exit codes: 0 ok, 1 findings at or above --fail-on, 2 usage or scan error.`;

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code: string) => (s: string) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const c = { bold: paint("1"), dim: paint("2"), red: paint("31"), green: paint("32"), yellow: paint("33"), magenta: paint("35"), gray: paint("90") };
const SEVERITY_COLOR: Record<Severity, (s: string) => string> = { critical: c.red, high: c.magenta, medium: c.yellow, low: c.gray };

function printPretty(result: ScanResult): void {
  const { summary } = result;
  console.log(`\n${c.bold("marcal-scan")} ${c.dim(result.repoUrl)}\n`);
  if (summary.total === 0) {
    console.log(c.green("✓ No exposed secrets found.\n"));
    return;
  }
  const sorted = [...result.findings].sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
  for (const f of sorted) {
    const tag = SEVERITY_COLOR[f.severity](f.severity.toUpperCase().padEnd(8));
    console.log(`  ${tag} ${c.bold(formatRuleLabel(f.ruleId))}`);
    console.log(`           ${f.file}:${f.line}  ${c.dim(f.maskedSecret)}`);
  }
  const counts = SEVERITIES.filter((s) => summary[s] > 0).map((s) => SEVERITY_COLOR[s](`${summary[s]} ${s}`));
  console.log(`\n${c.bold(`${summary.total} finding${summary.total === 1 ? "" : "s"}`)}: ${counts.join(", ")}\n`);
}

function fail(message: string): never {
  console.error(`marcal-scan: ${message}`);
  process.exit(2);
}

async function main(): Promise<void> {
  let parsed;
  try {
    parsed = parseArgs({
      allowPositionals: true,
      options: {
        format: { type: "string", default: "pretty" },
        html: { type: "string" },
        pdf: { type: "string" },
        sarif: { type: "string" },
        "fail-on": { type: "string", default: "none" },
        help: { type: "boolean", short: "h" },
        version: { type: "boolean", short: "v" },
      },
    });
  } catch (err) {
    fail(`${err instanceof Error ? err.message : err}\n\n${HELP}`);
  }
  const { values, positionals } = parsed;

  if (values.help) return void console.log(HELP);
  if (values.version) return void console.log(VERSION);
  if (positionals.length !== 1) fail(`expected exactly one target.\n\n${HELP}`);

  const format = values.format!;
  if (!["pretty", "json", "sarif"].includes(format)) fail(`unknown --format "${format}"`);
  const failOn = values["fail-on"]!;
  if (failOn !== "none" && !SEVERITIES.includes(failOn as Severity)) fail(`unknown --fail-on "${failOn}"`);

  const target = positionals[0];
  const remote = parseGithubUrl(target);
  // Anything URL-shaped must be a valid GitHub URL; otherwise path.resolve()
  // would quietly turn e.g. "https://github.com/../.." into the current directory.
  if (!remote.ok && /^(https?:\/\/|(www\.)?github\.com\/)/i.test(target.trim())) fail(remote.error.message);
  const outcome = remote.ok ? await scanRepo(target) : await scanDirectory(target);
  if (!outcome.ok) fail(outcome.error.message);
  const { result } = outcome;

  if (format === "json") console.log(JSON.stringify(result, null, 2));
  else if (format === "sarif") console.log(JSON.stringify(toSarif(result), null, 2));
  else printPretty(result);

  if (values.sarif) await writeFile(values.sarif, JSON.stringify(toSarif(result), null, 2));
  if (values.html || values.pdf) {
    const html = renderReportHtml(result);
    if (values.html) await writeFile(values.html, html);
    if (values.pdf) {
      const { renderReportPdf } = await import("./pdf.js");
      await writeFile(values.pdf, await renderReportPdf(html));
    }
  }

  if (failOn !== "none") {
    const threshold = SEVERITIES.indexOf(failOn as Severity);
    if (result.findings.some((f) => SEVERITIES.indexOf(f.severity) <= threshold)) process.exitCode = 1;
  }
}

main().catch((err) => fail(err instanceof Error ? err.message : String(err)));
