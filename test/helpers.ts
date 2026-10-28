import { randomInt } from "node:crypto";
import { execFileSync } from "node:child_process";
import type { RawGitleaksFinding } from "../src/gitleaks.js";

// Test secrets are generated at runtime so no secret-shaped string is ever
// committed — this repo scans itself in CI, and GitHub push protection would
// also (rightly) block a hard-coded token.
export function fakeGithubToken(): string {
  const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let body = "";
  for (let i = 0; i < 36; i++) body += alphabet[randomInt(alphabet.length)];
  return "ghp" + "_" + body;
}

export function rawFinding(overrides: Partial<RawGitleaksFinding> = {}): RawGitleaksFinding {
  return {
    RuleID: "github-pat",
    Description: "GitHub token",
    StartLine: 3,
    File: "src/config.ts",
    Secret: fakeGithubToken(),
    ...overrides,
  };
}

export function gitleaksAvailable(): boolean {
  try {
    execFileSync(process.env.GITLEAKS_BIN || "gitleaks", ["version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}
