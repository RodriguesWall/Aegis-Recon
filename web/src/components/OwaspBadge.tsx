// OwaspBadge renders an OWASP Top 10 (2021) category code as a small chip with
// the full category name as a tooltip. Renders nothing when the code is empty
// (findings that do not map to a web Top-10 category).

export const OWASP_NAMES: Record<string, string> = {
  A01: "Broken Access Control",
  A02: "Cryptographic Failures",
  A03: "Injection",
  A04: "Insecure Design",
  A05: "Security Misconfiguration",
  A06: "Vulnerable and Outdated Components",
  A07: "Identification and Authentication Failures",
  A08: "Software and Data Integrity Failures",
  A09: "Security Logging and Monitoring Failures",
  A10: "Server-Side Request Forgery",
}

export function OwaspBadge({ code }: { code?: string }) {
  if (!code) return null
  const name = OWASP_NAMES[code] ?? code
  return (
    <span
      title={`OWASP ${code} · ${name}`}
      className="whitespace-nowrap rounded border border-white/15 px-1.5 py-0.5 text-[10px] font-semibold text-muted"
    >
      {code}
    </span>
  )
}
