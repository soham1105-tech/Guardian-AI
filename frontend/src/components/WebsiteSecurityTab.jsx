// WebsiteSecurityTab.jsx — passive website-security assessment (Module 5)
//
// Every finding here comes from deterministic backend checks (security headers,
// HTTP configuration, two fixed-path exposure probes). The AI verdict may
// explain them but never produces them.

import Icon from "./Icon";
import { severityTone, TONE_TEXT } from "../lib/risk";

function Severity({ value }) {
  const label = String(value || "").toLowerCase();
  if (!label) return null;
  return (
    <span className="sev shrink-0">
      <span className={`dot ${TONE_TEXT[severityTone(label)]}`} />
      <span className="capitalize">{label}</span>
    </span>
  );
}

function Detail({ label, children }) {
  if (!children) return null;
  return (
    <p className="text-[12.5px] leading-relaxed">
      <span className="text-[var(--text-muted)]">{label}: </span>
      <span className="text-[var(--text-secondary)]">{children}</span>
    </p>
  );
}

function Metric({ label, value }) {
  return (
    <div className="inset px-3 py-2.5">
      <span className="label text-[9.5px]">{label}</span>
      <p className="num mt-1 text-[12.5px] text-[var(--text-primary)]">{value ?? "—"}</p>
    </div>
  );
}

function WebsiteSecurityTab({ websiteSecurity }) {
  if (!websiteSecurity) {
    return (
      <div className="surface flex flex-col items-center gap-3 px-6 py-12 text-center">
        <span className="grid h-10 w-10 place-items-center rounded-full border border-[var(--border)] bg-[var(--bg-secondary)] text-[var(--text-muted)]">
          <Icon name="globe" size={17} />
        </span>
        <div>
          <p className="text-[13.5px] font-medium">No website assessment</p>
          <p className="mt-1 text-[12.5px] text-[var(--text-muted)]">
            This report has no fetched web destination to assess.
          </p>
        </div>
      </div>
    );
  }

  const { status, summary, findings = [], headers = {}, http = {}, not_exposed: notExposed = [] } =
    websiteSecurity;
  const available = status === "assessed";
  const presentCount = Object.values(headers).filter((h) => h?.present).length;
  const totalHeaders = Object.keys(headers).length;
  const severeFindings = findings.filter((f) => ["High", "Critical"].includes(f.severity)).length;

  return (
    <div className="space-y-3">
      {/* Summary */}
      <div className="surface p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h3 className="text-[15px] font-semibold">Website security</h3>
            <p className="mt-1 text-[12.5px] text-[var(--text-muted)]">
              Passive checks only — no payloads, forms or credentials.
            </p>
          </div>
          <span className={`pill tone-${available ? (severeFindings > 0 ? "danger" : "safe") : "neutral"}`}>
            <span className="pill-dot" />
            {available ? `${severeFindings} high or critical` : "Unavailable"}
          </span>
        </div>

        <p className="mt-4 text-[13px] leading-relaxed text-[var(--text-secondary)]">{summary}</p>

        <div className="mt-4 grid grid-cols-1 gap-2 sm:grid-cols-3">
          <Metric
            label="Security headers"
            value={available ? `${presentCount} of ${totalHeaders} present` : "—"}
          />
          <Metric
            label="Scheme"
            value={
              available ? `${http.submitted_scheme || "—"} → ${http.final_scheme || "—"}` : "—"
            }
          />
          <Metric label="TLS" value={available ? http.tls_version || http.tls_status : "—"} />
        </div>

        {available && http.redirects_to_https && (
          <p className="mt-3 flex items-start gap-2 text-[12px] text-[var(--text-muted)]">
            <span className="mt-[2px]">
              <Icon name="info" size={13} />
            </span>
            Plain HTTP redirects to HTTPS before any content is served.
          </p>
        )}

        <p className="mt-3 text-[11.5px] leading-relaxed text-[var(--text-muted)]">
          One unauthenticated request per page, plus single GETs to{" "}
          <span className="text-[var(--text-secondary)]">/.env</span> and{" "}
          <span className="text-[var(--text-secondary)]">/.git/HEAD</span>.
        </p>
      </div>

      {/* Findings */}
      {findings.length > 0 && (
        <div className="surface p-5">
          <div className="flex items-baseline justify-between gap-3">
            <h3 className="text-[15px] font-semibold">Findings</h3>
            <span className="num text-[12px] text-[var(--text-muted)]">{findings.length}</span>
          </div>

          <ul className="mt-3 divide-y divide-[var(--border)]">
            {findings.map((finding, i) => (
              <li key={i} className="space-y-1.5 py-3.5 first:pt-0 last:pb-0">
                <div className="flex flex-wrap items-start justify-between gap-2">
                  <span className="text-[13px] font-medium text-[var(--text-primary)]">
                    {finding.issue}
                  </span>
                  <Severity value={finding.severity} />
                </div>
                <Detail label="Technical evidence">{finding["technical evidence"]}</Detail>
                <Detail label="Potential impact">{finding["potential impact"]}</Detail>
                <Detail label="Remediation">{finding["recommended remediation"]}</Detail>
                <Detail label="Limitation">{finding["relevant limitation"]}</Detail>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Paths that were checked and are not exposed (not findings) */}
      {notExposed.length > 0 && (
        <div className="surface p-5">
          <h3 className="text-[15px] font-semibold">Exposed endpoint probe</h3>
          <ul className="mt-3 space-y-1.5">
            {notExposed.map((entry, i) => (
              <li key={i} className="flex flex-wrap items-baseline gap-2 text-[12px]">
                <span className="code text-[var(--text-secondary)]">{entry.path}</span>
                <span className="text-[var(--text-muted)]">— {entry.evidence}</span>
              </li>
            ))}
          </ul>
          <p className="mt-3 text-[11.5px] text-[var(--text-muted)]">
            A non-200 response is recorded as not exposed and is not a finding.
          </p>
        </div>
      )}
    </div>
  );
}

export default WebsiteSecurityTab;
