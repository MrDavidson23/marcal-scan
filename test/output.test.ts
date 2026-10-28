import { test } from "node:test";
import assert from "node:assert/strict";
import { buildFindings, maskSecret, summarize } from "../src/rules.js";
import { renderReportHtml } from "../src/report.js";
import { toSarif } from "../src/sarif.js";
import type { ScanResult } from "../src/types.js";
import { rawFinding } from "./helpers.js";

test("maskSecret never returns the full value", () => {
  assert.equal(maskSecret("short"), "*****");
  assert.equal(maskSecret("abc"), "****");
  const secret = "sk_live_" + "x".repeat(30) + "WXYZ";
  const masked = maskSecret(secret);
  assert.notEqual(masked, secret);
  assert.ok(masked.startsWith("sk_live_"));
  assert.ok(masked.endsWith("WXYZ"));
  assert.ok(masked.includes("****"));
});

test("buildFindings maps known rules and falls back for unknown ones", () => {
  const [known, unknown] = buildFindings([
    rawFinding(),
    rawFinding({ RuleID: "some-new-rule", Description: "Something gitleaks found" }),
  ]);
  assert.equal(known.severity, "high");
  assert.notEqual(known.maskedSecret, rawFinding().Secret);
  assert.equal(unknown.severity, "medium");
  assert.equal(unknown.description, "Something gitleaks found");
});

test("summarize counts by severity", () => {
  const findings = buildFindings([rawFinding(), rawFinding(), rawFinding({ RuleID: "aws-access-token" })]);
  assert.deepEqual(summarize(findings), { total: 3, critical: 1, high: 2, medium: 0, low: 0 });
});

function result(findings = buildFindings([rawFinding()])): ScanResult {
  return {
    repoFullName: "owner/repo",
    repoUrl: "https://github.com/owner/repo",
    scanDate: "2026-10-27T12:00:00.000Z",
    findings,
    summary: summarize(findings),
  };
}

test("HTML report escapes attacker-controlled file names and values", () => {
  const evil = '<img src=x onerror="alert(1)">.js';
  const html = renderReportHtml(result(buildFindings([rawFinding({ File: evil, Secret: "<script>x</script>" + "a".repeat(20) })])));
  assert.ok(!html.includes(evil));
  assert.ok(!html.includes("<script>x"));
  assert.ok(html.includes("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;.js"));
});

test("HTML report shows the clean banner when nothing is found", () => {
  const html = renderReportHtml(result([]));
  assert.ok(html.includes("No exposed secrets or API keys were detected"));
  assert.ok(!html.includes("<table>"));
});

test("SARIF output is valid-shaped and never contains the raw secret", () => {
  const raw = rawFinding();
  const sarif = toSarif(result(buildFindings([raw]))) as any;
  const text = JSON.stringify(sarif);
  assert.ok(!text.includes(raw.Secret));
  assert.equal(sarif.version, "2.1.0");
  const run = sarif.runs[0];
  assert.equal(run.tool.driver.rules[0].id, "github-pat");
  assert.equal(run.tool.driver.rules[0].properties["security-severity"], "8.0");
  assert.equal(run.results[0].level, "error");
  assert.equal(run.results[0].locations[0].physicalLocation.region.startLine, 3);
});

test("SARIF fingerprints are stable across runs", () => {
  const findings = buildFindings([rawFinding({ Secret: "ghp_" + "A".repeat(36) })]);
  const a = (toSarif(result(findings)) as any).runs[0].results[0].partialFingerprints;
  const b = (toSarif(result(findings)) as any).runs[0].results[0].partialFingerprints;
  assert.deepEqual(a, b);
});
