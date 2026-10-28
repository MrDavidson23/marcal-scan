import { createHash } from "node:crypto";
import { formatRuleLabel } from "./report.js";
import type { ScanResult, Severity } from "./types.js";
import { VERSION } from "./version.js";

const LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
};

// GitHub code scanning sorts and labels alerts by this property (0.1–10).
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: "9.5",
  high: "8.0",
  medium: "5.5",
  low: "3.0",
};

// SARIF 2.1.0 for GitHub code scanning (github/codeql-action/upload-sarif).
// Only masked values go in: SARIF files end up as build artifacts and in the
// Security tab, so the raw secret must never be written here.
export function toSarif(result: ScanResult): object {
  const rules = new Map<string, { id: string; severity: Severity; description: string }>();
  for (const f of result.findings) {
    if (!rules.has(f.ruleId)) rules.set(f.ruleId, { id: f.ruleId, severity: f.severity, description: f.description });
  }

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "marcal-scan",
            version: VERSION,
            informationUri: "https://github.com/MrDavidson23/marcal-scan",
            rules: [...rules.values()].map((r) => ({
              id: r.id,
              name: formatRuleLabel(r.id).replace(/\s+/g, ""),
              shortDescription: { text: `${formatRuleLabel(r.id)} exposed` },
              fullDescription: { text: r.description },
              defaultConfiguration: { level: LEVEL[r.severity] },
              properties: { tags: ["security", "secrets"], "security-severity": SECURITY_SEVERITY[r.severity] },
            })),
          },
        },
        results: result.findings.map((f) => ({
          ruleId: f.ruleId,
          level: LEVEL[f.severity],
          message: { text: `${formatRuleLabel(f.ruleId)} found: ${f.maskedSecret}. Rotate it, then remove it from the code.` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.file.split("\\").join("/") },
                region: { startLine: Math.max(1, f.line) },
              },
            },
          ],
          partialFingerprints: {
            "marcalScan/v1": createHash("sha256").update(`${f.ruleId}\0${f.file}\0${f.maskedSecret}`).digest("hex"),
          },
        })),
      },
    ],
  };
}
