import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { DEFAULT_LIMITS, ScanLimitError } from "./limits.js";

const execFileAsync = promisify(execFile);

// Raw gitleaks JSON finding, unredacted — never persisted or logged as-is.
// Only rules.ts's masked view of this leaves the library.
export type RawGitleaksFinding = {
  RuleID: string;
  Description: string;
  StartLine: number;
  File: string;
  Secret: string;
};

// GITLEAKS_BIN if explicitly set (the GitHub Action points it at a pinned,
// checksum-verified binary), else whatever's on PATH.
const GITLEAKS_BIN = process.env.GITLEAKS_BIN || "gitleaks";

// Without an explicit --config, gitleaks looks for .gitleaks.toml in the
// scan target directory *before* falling back to its own default ruleset —
// and the scan target can be a repo someone else controls. Left unset, an
// attacker could ship their own .gitleaks.toml to suppress findings or define
// a rule with a pathological regex to waste CPU on every scan. Vendored from
// gitleaks' own config/gitleaks.toml at the pinned version
// (scripts/install-gitleaks.mjs) so scanned repos can never influence the
// ruleset used against them — re-vendor this file if that version is bumped.
const GITLEAKS_CONFIG_PATH = fileURLToPath(new URL("../../config/gitleaks.toml", import.meta.url));

// Runs gitleaks against `sourceDir` and returns the unredacted findings.
// The JSON report is written OUTSIDE sourceDir and deleted before returning:
// writing it inside the scanned directory causes gitleaks to detect its own
// previous output as new findings on a re-scan.
export async function runGitleaks(
  sourceDir: string,
  timeoutMs: number = DEFAULT_LIMITS.gitleaksTimeoutMs
): Promise<RawGitleaksFinding[]> {
  const reportDir = await mkdtemp(join(tmpdir(), "marcal-scan-report-"));
  const reportPath = join(reportDir, "report.json");

  try {
    try {
      // cwd + "--source ." (rather than an absolute --source path) so
      // gitleaks reports findings with clean relative file paths.
      await execFileAsync(
        GITLEAKS_BIN,
        [
          "detect",
          "--no-git",
          "--no-banner",
          "--source",
          ".",
          "--config",
          GITLEAKS_CONFIG_PATH,
          "--report-format",
          "json",
          "--report-path",
          reportPath,
          "--exit-code",
          "0", // we read the report either way; a nonzero exit here would just mean "leaks found"
        ],
        { cwd: sourceDir, timeout: timeoutMs, killSignal: "SIGKILL", maxBuffer: 10 * 1024 * 1024 }
      );
    } catch (err) {
      if (err && typeof err === "object" && "killed" in err && err.killed) {
        throw new ScanLimitError(`gitleaks did not finish within ${timeoutMs} ms.`);
      }
      if (err && typeof err === "object" && "code" in err && err.code === "ENOENT") {
        throw new Error(`gitleaks binary not found ("${GITLEAKS_BIN}"). Install it (brew install gitleaks) or set GITLEAKS_BIN.`);
      }
      throw new Error(`gitleaks scan failed: ${err instanceof Error ? err.message : String(err)}`);
    }

    const raw = await readFile(reportPath, "utf8");
    return JSON.parse(raw) as RawGitleaksFinding[];
  } finally {
    await rm(reportDir, { recursive: true, force: true });
  }
}
