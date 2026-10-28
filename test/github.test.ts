import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, readdir, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as tar from "tar";
import { parseGithubUrl, extractTarball } from "../src/github.js";
import { DEFAULT_LIMITS, ScanLimitError } from "../src/limits.js";

test("parseGithubUrl accepts the common URL shapes", () => {
  for (const input of [
    "https://github.com/owner/repo",
    "http://github.com/owner/repo/",
    "github.com/owner/repo.git",
    "  https://www.github.com/my-org/my.repo  ",
  ]) {
    const parsed = parseGithubUrl(input);
    assert.ok(parsed.ok, input);
  }
  const parsed = parseGithubUrl("https://github.com/owner/repo.git");
  assert.deepEqual(parsed.ok && parsed.ref, { owner: "owner", repo: "repo" });
});

test("parseGithubUrl rejects other hosts, extra paths, and dot segments", () => {
  for (const input of [
    "https://gitlab.com/owner/repo",
    "https://github.com/owner",
    "https://github.com/owner/repo/tree/main",
    "https://github.com.evil.com/owner/repo",
    "https://github.com/../..",
    "https://github.com/owner/..",
    "https://github.com/./repo",
    "./local/folder",
  ]) {
    assert.equal(parseGithubUrl(input).ok, false, input);
  }
});

async function makeArchive(build: (root: string) => Promise<void>): Promise<{ dir: string; file: string }> {
  const dir = await mkdtemp(join(tmpdir(), "marcal-scan-test-"));
  const src = join(dir, "src");
  // GitHub tarballs wrap everything in one "<owner>-<repo>-<sha>/" folder,
  // which extractTarball strips.
  await mkdir(join(src, "owner-repo-abc123"), { recursive: true });
  await build(join(src, "owner-repo-abc123"));
  const file = join(dir, "archive.tar.gz");
  await tar.c({ gzip: true, file, cwd: src }, ["owner-repo-abc123"]);
  return { dir, file };
}

test("extractTarball extracts a normal archive and strips the top folder", async () => {
  const { dir, file } = await makeArchive(async (root) => {
    await writeFile(join(root, "index.js"), "console.log('hi')\n");
  });
  const out = join(dir, "out");
  await mkdir(out);
  await extractTarball(file, out);
  assert.deepEqual(await readdir(out), ["index.js"]);
  await rm(dir, { recursive: true, force: true });
});

test("extractTarball stops a decompression bomb at the byte limit", async () => {
  const { dir, file } = await makeArchive(async (root) => {
    // 4 MB of zeros compresses to a few KB.
    await writeFile(join(root, "bomb.bin"), Buffer.alloc(4 * 1024 * 1024));
  });
  const out = join(dir, "out");
  await mkdir(out);
  await assert.rejects(
    extractTarball(file, out, { ...DEFAULT_LIMITS, maxExtractedBytes: 1024 * 1024 }),
    ScanLimitError
  );
  await rm(dir, { recursive: true, force: true });
});

test("extractTarball stops at the entry limit", async () => {
  const { dir, file } = await makeArchive(async (root) => {
    for (let i = 0; i < 20; i++) await writeFile(join(root, `f${i}.txt`), "x");
  });
  const out = join(dir, "out");
  await mkdir(out);
  await assert.rejects(extractTarball(file, out, { ...DEFAULT_LIMITS, maxEntries: 10 }), ScanLimitError);
  await rm(dir, { recursive: true, force: true });
});

test("extractTarball skips symlinks", async () => {
  const { dir, file } = await makeArchive(async (root) => {
    await writeFile(join(root, "real.txt"), "ok");
    await symlink("/etc/passwd", join(root, "link"));
  });
  const out = join(dir, "out");
  await mkdir(out);
  await extractTarball(file, out);
  assert.deepEqual(await readdir(out), ["real.txt"]);
  await rm(dir, { recursive: true, force: true });
});
