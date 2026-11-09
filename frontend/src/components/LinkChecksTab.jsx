// LinkChecksTab.jsx — link-specific investigation detail (Module 1)

import Icon from "./Icon";
import { TONE_TEXT, severityTone } from "../lib/risk";

// Providers that publish an actual scan/blocklist verdict. AlienVault OTX only
// reports "appears in N community pulses", which is a narrative mention — so it
// must never be presented with the same authority as a scan verdict.
const SCAN_PROVIDERS = ["VirusTotal", "URLhaus", "URLScan.io", "AbuseIPDB"];

function Section({ title, badge, children }) {
  return (
    <section className="surface p-5">
      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <h3 className="text-[15px] font-semibold text-[var(--text-primary)]">{title}</h3>
        {badge}
      </div>
      <div className="mt-4 space-y-3">{children}</div>
    </section>
  );
}

function Severity({ value, className = "" }) {
  const label = String(value || "").toLowerCase();
  if (!label) return null;
  return (
    <span className={`sev shrink-0 ${className}`}>
      <span className={`dot ${TONE_TEXT[severityTone(label)]}`} />
      <span className="capitalize">{label}</span>
    </span>
  );
}

function Tag({ children, title }) {
  return (
    <span
      className="pill tone-neutral max-w-full truncate align-middle"
      title={title || undefined}
    >
      {children}
    </span>
  );
}

function ReputationBadge({ verdicts }) {
  const checked = verdicts.filter((v) => v.checked);
  const flagged = checked.filter((v) => v.malicious);
  const scanFlagged = flagged.filter((v) => SCAN_PROVIDERS.includes(v.provider));

  if (scanFlagged.length > 0) {
    const top = Math.max(...scanFlagged.map((v) => v.confidence));
    return (
      <span
        className="sev shrink-0"
        title={scanFlagged.map((v) => `${v.provider}: ${v.detail}`).join("\n")}
      >
        <span className="dot text-[var(--danger)]" />
        {scanFlagged.length} vendor{scanFlagged.length > 1 ? "s" : ""} flagged · {top}%
      </span>
    );
  }

  if (flagged.length > 0) {
    return (
      <span
        className="sev shrink-0"
        title={flagged.map((v) => `${v.provider}: ${v.detail}`).join("\n")}
      >
        <span className="dot text-[var(--warning)]" />
        Community pulse only
      </span>
    );
  }

  if (checked.length > 0) {
    return (
      <span
        className="sev shrink-0"
        title={checked.map((v) => `${v.provider}: ${v.detail}`).join("\n")}
      >
        <span className="dot text-[var(--success)]" />
        Clean
      </span>
    );
  }

  return (
    <span
      className="sev shrink-0"
      title={verdicts.map((v) => `${v.provider}: ${v.detail}`).join("\n")}
    >
      <span className="dot text-[var(--text-muted)]" />
      Unverified
    </span>
  );
}

function TlsRow({ label, value }) {
  return (
    <div className="inset px-3 py-2">
      <span className="label text-[9.5px]">{label}</span>
      <p className="code mt-1 text-[12px] text-[var(--text-primary)]">{value ?? "—"}</p>
    </div>
  );
}

function TlsSection({ tls }) {
  const status = tls.status || "not checked";
  const cert = tls.certificate;
  const chain = tls.chain || {};
  const ct = tls.ct || {};
  const findings = tls.findings || [];
  const hostname = tls.hostname || {};

  const severity = (tls.compromised_ca || {}).matched
    ? "critical"
    : ["expired", "not_yet_valid", "hostname_mismatch", "self_signed"].includes(status)
    ? "high"
    : ["untrusted_chain", "no_tls", "unreachable", "blocked"].includes(status)
    ? "medium"
    : "low";

  const chainTrusted =
    chain.trusted === true
      ? "yes (trusted CA chain)"
      : chain.trusted === false
      ? `no — ${chain.verification_error || "verification failed"}`
      : "unknown";

  return (
    <Section
      title="TLS certificate"
      badge={<Severity value={tls.status_label || status} />}
    >
      <p className="flex items-start gap-2 rounded-[var(--radius-control)] border border-dashed border-[var(--border)] px-3 py-2 text-[12px] text-[var(--text-muted)]">
        <span className={`mt-[2px] ${TONE_TEXT[severity]}`}>
          <Icon name="lock" size={13} />
        </span>
        <span>
          {tls.note || "A valid certificate does not mean the website is safe"}
        </span>
      </p>

      {cert ? (
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          <TlsRow
            label="Issued by"
            value={cert.issuer_organization || cert.issuer_common_name || cert.issuer}
          />
          <TlsRow label="Subject" value={cert.subject} />
          <TlsRow label="Valid from" value={cert.not_before} />
          <TlsRow label="Valid until" value={cert.not_after} />
          <TlsRow
            label="Hostname / SAN match"
            value={
              hostname.matches
                ? `yes — ${hostname.matched_value}`
                : `no — certificate does not cover ${hostname.checked_host || "this host"}`
            }
          />
          <TlsRow
            label="Key"
            value={`${cert.public_key_type || "unknown"}${
              cert.public_key_bits ? ` ${cert.public_key_bits} bits` : ""
            }`}
          />
          <TlsRow label="Signature algorithm" value={cert.signature_algorithm} />
          <TlsRow label="Chain" value={chainTrusted} />
          <TlsRow
            label="Protocol / cipher"
            value={`${chain.protocol || "—"} · ${chain.cipher || "—"}`}
          />
          <TlsRow
            label="Validity remaining"
            value={
              cert.expired
                ? "expired"
                : cert.days_remaining != null
                ? `${cert.days_remaining} day(s)`
                : "—"
            }
          />
        </div>
      ) : (
        <p className="rounded-[var(--radius-control)] border border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-2.5 text-[12px] text-[var(--text-muted)]">
          {tls.error || "No certificate was retrieved."}
        </p>
      )}

      {/* Certificate Transparency */}
      <div className="inset p-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="label text-[9.5px]">Certificate transparency</span>
          {ct.available && ct.recently_issued_count > 0 && (
            <Severity value="medium" />
          )}
        </div>

        {ct.available ? (
          <div className="mt-1.5 space-y-1">
            <p className="text-[12px] text-[var(--text-secondary)]">{ct.count_note}</p>
            <p className="num text-[11px] text-[var(--text-muted)]">
              {ct.recently_issued_count || 0} issued in the last {ct.window_days || 7} day(s)
              {ct.truncated ? " · partial crt.sh response" : ""}
              {ct.newest_not_before ? ` · newest ${ct.newest_not_before}` : ""}
            </p>
            {ct.recently_issued?.length > 0 && (
              <ul className="space-y-1 pt-1">
                {ct.recently_issued.map((entry, i) => (
                  <li key={i} className="code text-[10.5px] text-[var(--text-muted)]">
                    {entry.not_before} · {entry.common_name} · {entry.issuer}
                  </li>
                ))}
              </ul>
            )}
          </div>
        ) : (
          <p className="mt-1.5 text-[11.5px] text-[var(--text-muted)]">
            {ct.error || "CT log unavailable"} — the rest of the TLS analysis still ran.
          </p>
        )}
      </div>

      {findings.length > 0 && (
        <ul className="divide-y divide-[var(--border)]">
          {findings.map((finding, i) => (
            <li key={i} className="space-y-1 py-2.5 first:pt-0 last:pb-0">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-[12px] font-medium capitalize text-[var(--text-primary)]">
                  {String(finding.type || "").replace(/_/g, " ")}
                </span>
                <Severity value={finding.severity} />
              </div>
              <p className="code text-[12px] leading-relaxed text-[var(--text-secondary)]">
                {finding.evidence}
              </p>
              {finding.detail && (
                <p className="code text-[11px] leading-relaxed text-[var(--text-muted)]">
                  {finding.detail}
                </p>
              )}
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}

function LinkChecksTab({ checks, indicators = [], evidence = [], recommendations = [] }) {
  if (!checks) return null;

  const dns = checks.dns || {};
  const tls = checks.tls || {};
  const redirects = checks.redirects || {};
  const reputation = checks.reputation || {};
  const domainIntel = checks.domain_intel || {};
  const homograph = checks.homograph || {};
  const hops = redirects.hops || [];
  const reputationResults = reputation.results || {};

  const statusTone = (status) => {
    if (status == null) return TONE_TEXT.neutral;
    if (status >= 400) return TONE_TEXT.danger;
    if (status >= 300) return TONE_TEXT.warn;
    return TONE_TEXT.safe;
  };

  return (
    <div className="space-y-3">
      {/* Submitted vs normalised */}
      <Section title="URL normalisation">
        <div className="space-y-2">
          <div className="inset px-3 py-2.5">
            <span className="label text-[9.5px]">Submitted</span>
            <p className="code mt-1 text-[12px] text-[var(--text-secondary)]">
              {checks.submitted_url}
            </p>
          </div>
          <div className="inset px-3 py-2.5">
            <span className="label text-[9.5px]">Analysed (normalised)</span>
            <p className="code mt-1 text-[12px] text-[var(--text-primary)]">
              {checks.normalized_url}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            <Tag>host: {checks.host}</Tag>
            <Tag>domain: {checks.registered_domain}</Tag>
            {checks.tracking_params_removed?.length > 0 && (
              <Tag>{checks.tracking_params_removed.length} tracking param(s) stripped</Tag>
            )}
            {homograph.is_punycode && (
              <span className="sev">
                <span className="dot text-[var(--danger)]" />
                punycode → {checks.unicode_host}
              </span>
            )}
            {homograph.suspicious && (
              <span className="sev">
                <span className="dot text-[var(--danger)]" />
                Homograph risk
              </span>
            )}
            {domainIntel.suspicious_tld && (
              <span className="sev">
                <span className="dot text-[var(--danger)]" />
                Suspicious TLD .{checks.suffix}
              </span>
            )}
            {domainIntel.is_official_brand_domain && (
              <span className="sev">
                <span className="dot text-[var(--success)]" />
                Official brand domain
              </span>
            )}
          </div>

          {checks.normalization_notes?.length > 0 && (
            <ul className="space-y-1">
              {checks.normalization_notes.map((note, i) => (
                <li key={i} className="flex items-start gap-2 text-[12px]">
                  <span className="mt-[8px] h-1 w-1 shrink-0 rounded-full bg-[var(--text-muted)]" />
                  <span className="text-[var(--text-secondary)]">{note}</span>
                </li>
              ))}
            </ul>
          )}

          {homograph.reasons?.length > 0 && (
            <ul className="space-y-1">
              {homograph.reasons.map((reason, i) => (
                <li key={i} className="flex items-start gap-2 text-[12px]">
                  <span className="mt-[2px] text-[var(--danger)]">
                    <Icon name="alert" size={12} />
                  </span>
                  <span className="text-[var(--danger)]">{reason}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </Section>

      {/* TLS certificate */}
      <TlsSection tls={tls} />

      {/* DNS */}
      <Section
        title="DNS resolution"
        badge={
          <span className="sev">
            <span className={`dot ${dns.resolved ? TONE_TEXT.safe : TONE_TEXT.warn}`} />
            {dns.resolved ? "Resolved" : "Did not resolve"}
          </span>
        }
      >
        {dns.resolved ? (
          <div className="space-y-3">
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              {(dns.addresses || []).slice(0, 6).map((address) => (
                <div key={address} className="code inset px-3 py-2 text-[12px]">
                  {address}
                </div>
              ))}
            </div>
            {dns.mx?.length > 0 && (
              <p className="code text-[11.5px] text-[var(--text-muted)]">
                MX: {dns.mx.join(", ")}
              </p>
            )}
          </div>
        ) : (
          <div className="rounded-[var(--radius-control)] border border-[var(--warning-border)] bg-[var(--warning-bg)] px-3 py-2.5">
            <p className="text-[12px] text-[var(--warning)]">
              {dns.error || "The domain has no A/AAAA records."}
            </p>
            <p className="mt-1 text-[11px] text-[var(--text-muted)]">
              Recorded as evidence — the remaining checks still ran.
            </p>
          </div>
        )}
      </Section>

      {/* Redirect chain */}
      <Section
        title="Redirect chain"
        badge={
          <span className="num text-[12px] text-[var(--text-muted)]">
            {redirects.redirect_count || 0} / {redirects.max_hops || 5} hops
          </span>
        }
      >
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-left text-[12px]">
            <thead>
              <tr className="border-b border-[var(--border)]">
                {["#", "Status", "URL", "Note"].map((heading) => (
                  <th key={heading} className="label whitespace-nowrap py-2 pr-4 font-medium last:pr-0">
                    {heading}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {hops.length === 0 ? (
                <tr>
                  <td colSpan={4} className="py-3 text-[12px] text-[var(--text-muted)]">
                    No hops recorded — the destination did not resolve, so nothing was fetched.
                  </td>
                </tr>
              ) : (
                hops.map((hop) => (
                  <tr key={`${hop.hop}-${hop.url}`} className="border-b border-[var(--border)] last:border-0">
                    <td className="num py-2 pr-4 text-[var(--text-muted)]">{hop.hop}</td>
                    <td className={`num py-2 pr-4 font-medium ${statusTone(hop.status)}`}>
                      {hop.status ?? "—"}
                    </td>
                    <td className="code py-2 pr-4 text-[var(--text-secondary)]">
                      {hop.url}
                      {hop.title && (
                        <span className="mt-0.5 block text-[10.5px] text-[var(--text-muted)]">
                          title: {hop.title}
                        </span>
                      )}
                    </td>
                    <td className="code py-2 text-[10.5px] text-[var(--text-muted)]">
                      {hop.error || hop.location || hop.skipped_body_reason || "—"}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          <Tag>final: {redirects.final_host || "—"}</Tag>
          {redirects.domain_changed && (
            <span className="sev">
              <span className="dot text-[var(--danger)]" />
              Redirects to an unrelated domain
            </span>
          )}
          {redirects.scheme_downgrade && (
            <span className="sev">
              <span className="dot text-[var(--warning)]" />
              HTTPS → HTTP downgrade
            </span>
          )}
          {redirects.limit_exceeded && (
            <span className="sev">
              <span className="dot text-[var(--warning)]" />
              Hop limit exceeded
            </span>
          )}
          {redirects.loop_detected && (
            <span className="sev">
              <span className="dot text-[var(--warning)]" />
              Redirect loop
            </span>
          )}
          {redirects.page_title && <Tag>page title: {redirects.page_title}</Tag>}
        </div>
      </Section>

      {/* Reputation */}
      <Section
        title="Reputation lookups"
        badge={
          <span className="num text-[12px] text-[var(--text-muted)]">
            {reputation.summary?.malicious_ioc_count || 0} flagged
          </span>
        }
      >
        {Object.keys(reputationResults).length === 0 ? (
          <p className="text-[12px] text-[var(--text-muted)]">No reputation lookup was performed.</p>
        ) : (
          <div className="space-y-2">
            {Object.entries(reputationResults).map(([ioc, verdicts]) => (
              <div key={ioc} className="inset p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="code min-w-0 flex-1 text-[12px] text-[var(--text-primary)]">
                    {ioc}
                  </span>
                  <ReputationBadge verdicts={verdicts} />
                </div>
                <ul className="mt-1.5 space-y-1">
                  {verdicts.map((verdict, i) => (
                    <li
                      key={i}
                      className={`code text-[10.5px] ${
                        verdict.malicious ? "text-[var(--danger)]" : "text-[var(--text-muted)]"
                      }`}
                    >
                      {verdict.provider}: {verdict.detail}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
            {reputation.unavailable_providers?.length > 0 && (
              <p className="text-[11px] text-[var(--text-muted)]">
                Unavailable: {reputation.unavailable_providers.join(", ")} — set the matching API
                key to enable these feeds.
              </p>
            )}
          </div>
        )}
      </Section>

      {/* Domain intelligence */}
      {domainIntel.indicators?.length > 0 && (
        <Section title="Domain intelligence">
          <ul className="divide-y divide-[var(--border)]">
            {domainIntel.indicators.map((item, i) => (
              <li key={i} className="flex flex-wrap items-start gap-3 py-2.5 first:pt-0 last:pb-0">
                <Severity value={item.severity} className="min-w-[5.5rem]" />
                <span className="text-[12px] leading-relaxed text-[var(--text-secondary)]">
                  {item.detail}
                </span>
                <span className="ml-auto text-[10.5px] uppercase tracking-[0.08em] text-[var(--text-muted)]">
                  {item.type}
                </span>
              </li>
            ))}
          </ul>
        </Section>
      )}

      {/* Evidence trail */}
      {evidence.length > 0 && (
        <Section
          title="Evidence trail"
          badge={
            <span className="num text-[12px] text-[var(--text-muted)]">{evidence.length} finding(s)</span>
          }
        >
          <ul className="max-h-96 space-y-2 overflow-y-auto pr-1">
            {evidence.map((item, i) => (
              <li key={i} className="inset space-y-1 p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="label text-[9.5px] text-[var(--accent)]">{item.source}</span>
                  <Severity value={item.severity} />
                </div>
                <p className="code text-[12px] leading-relaxed text-[var(--text-secondary)]">
                  {item.finding}
                </p>
                {item.detail && (
                  <p className="code text-[10.5px] leading-relaxed text-[var(--text-muted)]">
                    {item.detail}
                  </p>
                )}
              </li>
            ))}
          </ul>
        </Section>
      )}

      {/* Recommendations */}
      {recommendations.length > 0 && (
        <Section title="Recommended actions">
          <ul className="divide-y divide-[var(--border)]">
            {recommendations.map((recommendation, i) => (
              <li key={i} className="flex items-start gap-2.5 py-2.5 first:pt-0 last:pb-0">
                <span className="mt-[2px] shrink-0 text-[var(--accent)]">
                  <Icon name="zap" size={13} />
                </span>
                <span className="text-[12.5px] leading-relaxed text-[var(--text-secondary)]">
                  {recommendation}
                </span>
              </li>
            ))}
          </ul>
        </Section>
      )}

      {/* Indicators */}
      {indicators.length > 0 && (
        <Section title="Indicators">
          <div className="flex flex-wrap gap-2">
            {indicators.map((indicator, i) => (
              <span key={i} className="sev rounded-full border border-[var(--border)] px-2.5 py-1">
                <span className={`dot ${TONE_TEXT[severityTone(indicator.severity)]}`} />
                <span className="text-[11.5px] text-[var(--text-secondary)]">
                  {indicator.type} · {indicator.severity}
                </span>
              </span>
            ))}
          </div>
        </Section>
      )}
    </div>
  );
}

export default LinkChecksTab;
