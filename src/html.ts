// Escapes untrusted text for safe interpolation into an HTML string. Needed
// anywhere HTML is hand-built from external input (e.g. the report, built from
// file paths and secret values found in a scanned repo — both fully
// attacker-controlled, since anyone can put any file name or fake "secret"
// string in a public repo).
export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
