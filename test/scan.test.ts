import { test } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { scanDirectory } from "../src/scan.js";
import { fakeGithubToken, gitleaksAvailable } from "./helpers.js";

const run = promisify(execFile);
const CLI = fileURLToPath(new URL("../src/cli.js", import.meta.url));
const skip = gitleaksAvailable() ? false : "gitleaks is not installed (set GITLEAKS_BIN or brew install gitleaks)";

async function repoWithLeak(): Promise<{ dir: string; token: string }> {
  const dir = await mkdtemp(join(tmpdir(), "marcal-scan-repo-"));
  const token = fakeGithubToken();
  await writeFile(join(dir, "config.js"), `// deploy settings\nconst a = 1;\nexport const token = "${token}";\n`);
  return { dir, token };
}

test("scanDirectory finds a leaked token and masks it", { skip }, async () => {
  const { dir, token } = await repoWithLeak();
  try {
    const outcome = await scanDirectory(dir);
    assert.ok(outcome.ok);
    const [finding] = outcome.result.findings;
    assert.equal(finding.ruleId, "github-pat");
    assert.equal(finding.file, "config.js");
    assert.equal(finding.line, 3);
    assert.notEqual(finding.maskedSecret, token);
    assert.ok(!JSON.stringify(outcome.result).includes(token));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("a scanned repo's own .gitleaks.toml cannot hide findings", { skip }, async () => {
  const { dir } = await repoWithLeak();
  // An attacker-controlled config that allowlists every path.
  await writeFile(join(dir, ".gitleaks.toml"), `title = "evil"\n[allowlist]\npaths = ['''.*''']\n`);
  try {
    const outcome = await scanDirectory(dir);
    assert.ok(outcome.ok);
    assert.equal(outcome.result.summary.high, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("scanDirectory reports a missing directory", async () => {
  const outcome = await scanDirectory("/definitely/not/here");
  assert.equal(outcome.ok, false);
});

test("CLI exits 1 when --fail-on threshold is met, 0 otherwise", { skip }, async () => {
  const { dir } = await repoWithLeak();
  try {
    await assert.rejects(run(process.execPath, [CLI, dir, "--fail-on", "high"]), (err: any) => err.code === 1);
    const { stdout } = await run(process.execPath, [CLI, dir, "--fail-on", "critical", "--format", "json"]);
    assert.equal(JSON.parse(stdout).summary.high, 1);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("CLI exits 2 on bad usage", async () => {
  await assert.rejects(run(process.execPath, [CLI]), (err: any) => err.code === 2);
  await assert.rejects(run(process.execPath, [CLI, ".", "--fail-on", "sometimes"]), (err: any) => err.code === 2);
});

test("CLI rejects invalid URLs instead of scanning the current directory", async () => {
  for (const target of ["https://github.com/../..", "https://gitlab.com/owner/repo", "github.com/owner"]) {
    await assert.rejects(
      run(process.execPath, [CLI, target]),
      (err: any) => err.code === 2 && /valid github\.com repository URL/.test(err.stderr),
      target
    );
  }
});
