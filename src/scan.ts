import { rm, stat } from "node:fs/promises";
import { basename, resolve } from "node:path";
import { parseGithubUrl, fetchRepoMetadata, downloadRepoSnapshot } from "./github.js";
import { runGitleaks } from "./gitleaks.js";
import { DEFAULT_LIMITS, ScanLimitError, type ScanLimits } from "./limits.js";
import { buildFindings, summarize } from "./rules.js";
import type { ScanResult, ScanError } from "./types.js";

export type ScanOutcome = { ok: true; result: ScanResult } | { ok: false; error: ScanError };

// fetch() rejects with a bare "fetch failed" and hides the real reason (DNS,
// TLS, connection refused) in err.cause — surface it so the user can act on it.
export function describeError(err: unknown): string {
  if (!(err instanceof Error)) return "Something went wrong while scanning the repository.";
  const cause = err.cause as { code?: string; hostname?: string; message?: string } | undefined;
  if (err.message === "fetch failed" && cause) {
    if (cause.code === "ENOTFOUND") {
      return `Network error: could not resolve ${cause.hostname ?? "host"} (DNS lookup failed). Check your connection or DNS settings.`;
    }
    const detail = [cause.code, cause.hostname].filter(Boolean).join(" ") || cause.message;
    return `Network error while contacting GitHub${detail ? `: ${detail}` : ""}.`;
  }
  return err.message;
}

function toScanError(err: unknown): ScanError {
  if (err instanceof ScanLimitError) return { code: "limit_exceeded", message: err.message };
  return { code: "scan_failed", message: describeError(err) };
}

// Validate the URL, confirm the repo is public, download a snapshot of its
// default branch, run gitleaks against it, and return masked findings. Always
// cleans up the downloaded source on the way out, scan failure or not.
export async function scanRepo(repoUrlInput: string, limits: ScanLimits = DEFAULT_LIMITS): Promise<ScanOutcome> {
  const parsed = parseGithubUrl(repoUrlInput);
  if (!parsed.ok) return { ok: false, error: parsed.error };

  let metaResult;
  try {
    metaResult = await fetchRepoMetadata(parsed.ref, limits);
  } catch (err) {
    return { ok: false, error: toScanError(err) };
  }
  if (!metaResult.ok) return { ok: false, error: metaResult.error };
  const { meta } = metaResult;

  let sourceDir: string | null = null;
  try {
    sourceDir = await downloadRepoSnapshot(parsed.ref, meta.defaultBranch, limits);
    const findings = buildFindings(await runGitleaks(sourceDir, limits.gitleaksTimeoutMs));
    return {
      ok: true,
      result: {
        repoFullName: meta.fullName,
        repoUrl: `https://github.com/${meta.fullName}`,
        scanDate: new Date().toISOString(),
        findings,
        summary: summarize(findings),
      },
    };
  } catch (err) {
    return { ok: false, error: toScanError(err) };
  } finally {
    if (sourceDir) await rm(sourceDir, { recursive: true, force: true }).catch(() => {});
  }
}

// Scans a directory already on disk (e.g. a CI checkout). Nothing is
// downloaded or deleted; the caller owns the directory.
export async function scanDirectory(dir: string, limits: ScanLimits = DEFAULT_LIMITS): Promise<ScanOutcome> {
  const path = resolve(dir);
  try {
    if (!(await stat(path)).isDirectory()) {
      return { ok: false, error: { code: "not_found", message: `${dir} is not a directory.` } };
    }
  } catch {
    return { ok: false, error: { code: "not_found", message: `${dir} does not exist.` } };
  }

  try {
    const findings = buildFindings(await runGitleaks(path, limits.gitleaksTimeoutMs));
    return {
      ok: true,
      result: {
        repoFullName: basename(path),
        repoUrl: path,
        scanDate: new Date().toISOString(),
        findings,
        summary: summarize(findings),
      },
    };
  } catch (err) {
    return { ok: false, error: toScanError(err) };
  }
}
