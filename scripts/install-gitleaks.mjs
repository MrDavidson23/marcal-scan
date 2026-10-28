// Downloads the pinned gitleaks release for the current platform, verifies
// its SHA-256 against the value below, and extracts only the binary.
// Used by the GitHub Action (action.yml) and CI.
//
//   node scripts/install-gitleaks.mjs <output-dir>
//
// Version is pinned for reproducible builds, and must match the vendored
// config/gitleaks.toml. To bump: take the new version's checksums from the
// release's gitleaks_<version>_checksums.txt, update the constants below,
// and re-vendor config/gitleaks.toml from the same tag.
import { mkdir, writeFile, rm, chmod } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join, resolve } from "node:path";
import * as tar from "tar";

const GITLEAKS_VERSION = "8.30.1";
const SHA256 = {
  linux_x64: "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
};

async function main() {
  const outDir = resolve(process.argv[2] ?? "bin/gitleaks");
  const arch = process.arch === "x64" ? "x64" : process.arch;
  const platform = `${process.platform}_${arch}`;
  const expected = SHA256[platform];
  if (!expected) {
    throw new Error(`No pinned gitleaks checksum for ${platform}. Install gitleaks yourself and set GITLEAKS_BIN.`);
  }

  const asset = `gitleaks_${GITLEAKS_VERSION}_${platform}.tar.gz`;
  const url = `https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${asset}`;
  console.log(`install-gitleaks: downloading gitleaks v${GITLEAKS_VERSION} (${platform})`);
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Failed to download gitleaks: ${res.status} ${res.statusText}`);
  const buffer = Buffer.from(await res.arrayBuffer());

  const actual = createHash("sha256").update(buffer).digest("hex");
  if (actual !== expected) {
    throw new Error(`gitleaks checksum mismatch: expected ${expected}, got ${actual}. Refusing to install.`);
  }

  await mkdir(outDir, { recursive: true });
  const tarball = join(outDir, "archive.tar.gz");
  await writeFile(tarball, buffer);
  try {
    // The release tarball is LICENSE, README.md, and the binary at its root.
    await tar.x({ file: tarball, cwd: outDir, filter: (path) => path === "gitleaks" });
  } finally {
    await rm(tarball, { force: true });
  }
  const bin = join(outDir, "gitleaks");
  await chmod(bin, 0o755);
  console.log(`install-gitleaks: installed ${bin}`);
}

main().catch((err) => {
  console.error(err.message ?? err);
  process.exit(1);
});
