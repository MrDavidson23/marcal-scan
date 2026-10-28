import { mkdtemp, open, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as tar from "tar";
import { DEFAULT_LIMITS, ScanLimitError, type ScanLimits } from "./limits.js";
import type { ScanError } from "./types.js";

const GITHUB_URL_RE = /^(?:https?:\/\/)?(?:www\.)?github\.com\/([\w.-]+)\/([\w.-]+?)(?:\.git)?\/?$/i;

// "." and ".." match the character class above but are path segments, not
// names — let through, they'd turn api.github.com/repos/{owner}/{repo} into a
// different API path.
const DOTS_ONLY = /^\.+$/;

export type RepoRef = { owner: string; repo: string };

export function parseGithubUrl(input: string): { ok: true; ref: RepoRef } | { ok: false; error: ScanError } {
  const match = GITHUB_URL_RE.exec(input.trim());
  if (!match || DOTS_ONLY.test(match[1]) || DOTS_ONLY.test(match[2])) {
    return {
      ok: false,
      error: { code: "invalid_url", message: "Enter a valid github.com repository URL, e.g. https://github.com/owner/repo" },
    };
  }
  return { ok: true, ref: { owner: match[1], repo: match[2] } };
}

function authHeaders(): HeadersInit {
  const token = process.env.GITHUB_TOKEN;
  const base = { "User-Agent": "marcal-scan", Accept: "application/vnd.github+json" };
  return token ? { ...base, Authorization: `Bearer ${token}` } : base;
}

type RepoMetadata = { fullName: string; defaultBranch: string; sizeKb: number };

export async function fetchRepoMetadata(
  ref: RepoRef,
  limits: ScanLimits = DEFAULT_LIMITS
): Promise<{ ok: true; meta: RepoMetadata } | { ok: false; error: ScanError }> {
  const res = await fetch(`https://api.github.com/repos/${ref.owner}/${ref.repo}`, {
    headers: authHeaders(),
  });

  if (res.status === 404) {
    return { ok: false, error: { code: "not_found", message: "Repository not found. Check the URL and that it's public." } };
  }
  if (!res.ok) {
    return { ok: false, error: { code: "not_found", message: `GitHub API error (${res.status}) while looking up the repository.` } };
  }

  const data = (await res.json()) as { full_name: string; private: boolean; default_branch: string; size: number };

  if (data.private) {
    return { ok: false, error: { code: "private_repo", message: "This repository is private. Only public repositories can be scanned." } };
  }
  if (data.size > limits.maxRepoSizeKb) {
    return { ok: false, error: { code: "repo_too_large", message: "This repository is too large to scan." } };
  }

  return { ok: true, meta: { fullName: data.full_name, defaultBranch: data.default_branch, sizeKb: data.size } };
}

// Streams the response body to disk, aborting as soon as it passes the cap —
// GitHub's reported repo size doesn't bound the tarball, and Content-Length
// may be absent on a chunked response.
async function downloadToFile(res: Response, path: string, maxBytes: number): Promise<void> {
  const declared = Number(res.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new ScanLimitError(`Repository archive is larger than the ${maxBytes} byte download limit.`);
  }

  const reader = res.body!.getReader();
  const file = await open(path, "w");
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new ScanLimitError(`Repository archive is larger than the ${maxBytes} byte download limit.`);
      }
      await file.write(value);
    }
  } finally {
    await file.close();
  }
}

// Extracts with a running byte and entry count. A small archive can expand to
// many gigabytes (a decompression bomb), so the compressed size check alone
// isn't enough. Links are skipped outright: gitleaks doesn't need them, and
// they're the usual vehicle for writing outside the extraction directory.
export async function extractTarball(file: string, cwd: string, limits: ScanLimits = DEFAULT_LIMITS): Promise<void> {
  let bytes = 0;
  let entries = 0;
  let exceeded: string | null = null;

  await tar.x({
    file,
    cwd,
    strip: 1,
    filter: (_path, entry) => {
      if (exceeded) return false;
      if ("type" in entry && (entry.type === "SymbolicLink" || entry.type === "Link")) return false;
      entries++;
      bytes += entry.size ?? 0;
      if (entries > limits.maxEntries) exceeded = `more than ${limits.maxEntries} files`;
      else if (bytes > limits.maxExtractedBytes) exceeded = `more than ${limits.maxExtractedBytes} bytes when extracted`;
      return !exceeded;
    },
  });

  if (exceeded) throw new ScanLimitError(`Repository archive contains ${exceeded}.`);
}

// Downloads a tarball of the default branch's HEAD and extracts it into a
// fresh temp directory — the same content a `git clone --depth 1` would give
// us, without needing a `git` binary in the runtime. Caller owns cleanup of
// the returned directory.
export async function downloadRepoSnapshot(
  ref: RepoRef,
  defaultBranch: string,
  limits: ScanLimits = DEFAULT_LIMITS
): Promise<string> {
  const res = await fetch(
    `https://api.github.com/repos/${ref.owner}/${ref.repo}/tarball/${encodeURIComponent(defaultBranch)}`,
    { headers: authHeaders() }
  );

  if (!res.ok || !res.body) {
    throw new Error(`Failed to download repository tarball (${res.status})`);
  }

  const dir = await mkdtemp(join(tmpdir(), "marcal-scan-src-"));
  const tarballPath = join(dir, "archive.tar.gz");

  try {
    await downloadToFile(res, tarballPath, limits.maxDownloadBytes);
    await extractTarball(tarballPath, dir, limits);
  } catch (err) {
    await rm(dir, { recursive: true, force: true });
    throw err;
  } finally {
    // Never leave the compressed archive sitting alongside the extracted
    // source — gitleaks would otherwise also scan it as one opaque binary.
    await rm(tarballPath, { force: true });
  }

  return dir;
}
