export type Severity = "critical" | "high" | "medium" | "low";

export type ScanFinding = {
  ruleId: string;
  description: string;
  severity: Severity;
  file: string;
  line: number;
  maskedSecret: string;
};

export type ScanSummary = {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
};

export type ScanResult = {
  repoFullName: string;
  repoUrl: string;
  scanDate: string;
  findings: ScanFinding[];
  summary: ScanSummary;
};

export type ScanError = {
  code: "invalid_url" | "not_found" | "private_repo" | "repo_too_large" | "limit_exceeded" | "scan_failed";
  message: string;
};
