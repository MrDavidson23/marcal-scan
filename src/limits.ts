// Every repository scanned is untrusted input. These caps bound how much a
// single scan can download, write to disk, and spend in gitleaks, so a
// hostile repo (a decompression bomb, millions of tiny files, or a file
// crafted to make a rule's regex crawl) can't exhaust the machine running it.
export type ScanLimits = {
  /** Repos GitHub reports as larger than this (KB) are rejected before downloading. */
  maxRepoSizeKb: number;
  /** Hard cap on the compressed tarball, enforced while streaming. */
  maxDownloadBytes: number;
  /** Hard cap on the total size of extracted files. */
  maxExtractedBytes: number;
  /** Hard cap on the number of entries in the archive. */
  maxEntries: number;
  /** gitleaks is killed after this many milliseconds. */
  gitleaksTimeoutMs: number;
};

export const DEFAULT_LIMITS: ScanLimits = {
  maxRepoSizeKb: 300 * 1024,
  maxDownloadBytes: 250 * 1024 * 1024,
  maxExtractedBytes: 1024 * 1024 * 1024,
  maxEntries: 100_000,
  gitleaksTimeoutMs: 120_000,
};

export class ScanLimitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScanLimitError";
  }
}
