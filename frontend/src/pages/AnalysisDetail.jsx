import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { getAnalysisById } from "../services/api";

import RiskGauge from "../components/RiskGauge";
import HeaderTab from "../components/HeaderTab";
import UrlTab from "../components/UrlTab";
import AttachmentTab from "../components/AttachmentTab";
import IocTab from "../components/IocTab";
import AiVerdictTab from "../components/AiVerdictTab";
import MitreTab from "../components/MitreTab";
import LinkChecksTab from "../components/LinkChecksTab";
import WebsiteSecurityTab from "../components/WebsiteSecurityTab";
import CampaignCard from "../components/CampaignCard";
import BlockchainRegistry from "../components/BlockchainRegistry";
import Icon from "../components/Icon";
import { categoryTone, categoryLabel, toneClass, toneVar, severityTone, TONE_TEXT } from "../lib/risk";

const BASE_TABS = [
  "Link Checks",
  "Headers",
  "URLs",
  "Attachments",
  "IOCs",
  "Website Security",
  "MITRE ATT&CK",
  "AI Verdict",
];

function hexToRgb(hex) {
  const m = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex || "");
  if (!m) return null;
  return { r: parseInt(m[1], 16), g: parseInt(m[2], 16), b: parseInt(m[3], 16) };
}

function toneRgb(tone) {
  const map = {
    safe: "#34d399",
    warn: "#fbbf24",
    high: "#fb923c",
    danger: "#f87171",
    accent: "#22d3ee",
    neutral: "#888899",
  };
  return hexToRgb(map[tone] || map.neutral);
}

function SectionPanel({ label, children }) {
  return (
    <section className="surface" style={{ overflow: "hidden" }}>
      <div
        className="section-label"
        style={{
          padding: "14px 18px",
          borderBottom: "1px solid var(--border)",
        }}
      >
        {label}
      </div>
      <div style={{ padding: "4px 18px" }}>{children}</div>
    </section>
  );
}

function DividerRow({ children }) {
  return (
    <div
      style={{
        padding: "12px 0",
        borderBottom: "1px solid var(--border)",
      }}
    >
      {children}
    </div>
  );
}

function SeverityDot({ severity, text }) {
  const sev = severityTone(severity);
  return (
    <span className="sev">
      <span className={`dot ${TONE_TEXT[sev]}`} />
      <span style={{ color: "var(--text-secondary)" }}>{text || String(severity || "").toLowerCase()}</span>
    </span>
  );
}

function TlsSummary({ tls }) {
  if (!tls) {
    return (
      <DividerRow>
        <span style={{ color: "var(--text-muted)", fontSize: 13 }}>No TLS data available for this report.</span>
      </DividerRow>
    );
  }
  const findings = Array.isArray(tls.findings) ? tls.findings.slice(0, 6) : [];
  const cert = tls.certificate;
  const rows = [];
  if (tls.status_label || tls.status) {
    rows.push({ severity: tls.status === "valid" || tls.status === "ok" ? "low" : "medium", text: `Status: ${tls.status_label || tls.status}` });
  }
  if (cert?.issuer_organization || cert?.issuer) {
    rows.push({ severity: "info", text: `Issuer: ${cert.issuer_organization || cert.issuer}` });
  }
  if (cert?.not_after) {
    rows.push({ severity: cert.expired ? "high" : "info", text: `Valid until: ${cert.not_after}` });
  }
  if (tls.hostname?.matches === true) {
    rows.push({ severity: "low", text: `Hostname match: ${tls.hostname.matched_value || "yes"}` });
  } else if (tls.hostname?.matches === false) {
    rows.push({ severity: "high", text: `Hostname mismatch for ${tls.hostname.checked_host || "host"}` });
  }
  if (tls.error) {
    rows.push({ severity: "medium", text: tls.error });
  }
  const display = rows.length ? rows : findings.map((f) => ({ severity: f.severity, text: f.evidence || f.issue || f.type || "Finding" }));
  if (display.length === 0 && tls.note) {
    return (
      <DividerRow>
        <span style={{ color: "var(--text-secondary)", fontSize: 13 }}>{tls.note}</span>
      </DividerRow>
    );
  }
  return (
    <div>
      {display.map((row, i) => (
        <DividerRow key={i}>
          <div style={{ display: "flex", alignItems: "flex-start", gap: 10 }}>
            <SeverityDot severity={row.severity} />
            <span className="mono" style={{ color: "var(--text-body)", fontSize: 13, lineHeight: 1.5 }}>
              {row.text}
            </span>
          </div>
        </DividerRow>
      ))}
      {tls.note && (
        <div style={{ padding: "12px 0", color: "var(--text-muted)", fontSize: 12 }}>
          {tls.note}
        </div>
      )}
    </div>
  );
}

function WebsiteSecuritySummary({ websiteSecurity }) {
  if (!websiteSecurity) {
    return (
      <DividerRow>
        <span style={{ color: "var(--text-muted)", fontSize: 13 }}>No website security assessment available.</span>
      </DividerRow>
    );
  }
  const findings = Array.isArray(websiteSecurity.findings) ? websiteSecurity.findings.slice(0, 6) : [];
  if (findings.length === 0) {
    return (
      <DividerRow>
        <span style={{ color: "var(--text-secondary)", fontSize: 13 }}>
          {websiteSecurity.summary || websiteSecurity.status || "No findings reported."}
        </span>
      </DividerRow>
    );
  }
  return (
    <div>
      {findings.map((f, i) => (
        <DividerRow key={i}>
          <div style={{ display: "flex", alignItems: "flex-start", gap: 10 }}>
            <SeverityDot severity={f.severity} />
            <span style={{ color: "var(--text-body)", fontSize: 13, lineHeight: 1.5 }}>
              {f.issue || f.title || f.evidence || "Finding"}
            </span>
          </div>
        </DividerRow>
      ))}
    </div>
  );
}

function AnalysisDetail() {
  const { emailId } = useParams();
  const [data, setData] = useState(null);
  const [activeTab, setActiveTab] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getAnalysisById(emailId)
      .then(setData)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [emailId]);

  if (loading) {
    return (
      <div style={{ maxWidth: 1100, margin: "0 auto" }}>
        <div style={{ height: 14, width: 160, borderRadius: 999, background: "var(--bg-card-hover)" }} />
        <div className="surface" style={{ marginTop: 20, height: 220 }} />
      </div>
    );
  }

  if (!data) {
    return (
      <div className="surface" style={{ maxWidth: 560, margin: "0 auto", padding: 32, textAlign: "center" }}>
        <div style={{ display: "grid", placeItems: "center", marginBottom: 12 }}>
          <Icon name="alert" size={20} />
        </div>
        <h1 style={{ fontSize: 18, fontWeight: 600 }}>Report not found</h1>
        <p style={{ marginTop: 8, color: "var(--text-muted)", fontSize: 14 }}>
          This investigation is not in the local report store.
        </p>
        <Link to="/" className="btn btn-secondary" style={{ marginTop: 16, display: "inline-flex" }}>
          <Icon name="arrow-left" size={14} /> Back
        </Link>
      </div>
    );
  }

  const isLink = Boolean(data.checks);
  const category = data.risk_report?.category;
  const tone = categoryTone(category);
  const label = categoryLabel(category);
  const rgb = toneRgb(tone);
  const bandBg = rgb ? `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, 0.06)` : "var(--bg-panel)";
  const bandBorder = rgb ? `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, 0.2)` : "var(--border)";
  const bandGlow = toneVar(tone);

  const aiExplanation =
    data.ai_verdict?.explanation ||
    data.ai_verdict?.summary ||
    data.risk_report?.summary ||
    "Verdict built from deterministic checks; see evidence below.";

  // Key evidence (2-3 lines max)
  const evidenceItems = Array.isArray(data.evidence) ? data.evidence : [];
  const indicatorItems = Array.isArray(data.indicators) ? data.indicators : [];
  const keyEvidence = [];
  for (const ev of evidenceItems) {
    if (keyEvidence.length >= 3) break;
    const text = ev.evidence || ev.finding || ev.detail || ev.issue;
    if (text) keyEvidence.push(text);
  }
  if (keyEvidence.length < 3) {
    for (const ind of indicatorItems) {
      if (keyEvidence.length >= 3) break;
      const text = ind.evidence || ind.value || ind.type;
      if (text && !keyEvidence.includes(text)) keyEvidence.push(`${ind.type || "Indicator"}: ${text}`);
    }
  }

  const websiteSecurity = data.checks?.website_security || data.website_security || null;
  const tls = data.checks?.tls || data.tls || null;
  const threatIntelResults = data.threat_intel?.results || {};
  const mitreTechniques = data.mitre_techniques || [];
  const tabs = isLink ? BASE_TABS : BASE_TABS.filter((t) => t !== "Link Checks");

  return (
    <div style={{ maxWidth: 1100, margin: "0 auto" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, marginBottom: 16 }}>
        <Link
          to="/"
          className="inline-flex items-center gap-2"
          style={{ fontSize: 13, color: "var(--text-secondary)", textDecoration: "none" }}
        >
          <Icon name="arrow-left" size={14} />
          All investigations
        </Link>
        <span style={{ fontSize: 12, color: "var(--text-muted)" }}>
          {isLink ? "Link investigation" : data.investigation_type === "message" ? "Message investigation" : "Email investigation"}
        </span>
      </div>

      {/* Verdict band */}
      <section
        className="verdict-band"
        style={{
          background: bandBg,
          borderColor: bandBorder,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 28, flexWrap: "wrap" }}>
          <div style={{ flex: "none" }}>
            <RiskGauge score={data.risk_report?.score} category={category} />
          </div>
          <div style={{ flex: 1, minWidth: 260 }}>
            <span
              className="pill"
              style={{
                color: bandGlow,
                background: `rgba(${rgb?.r ?? 136}, ${rgb?.g ?? 136}, ${rgb?.b ?? 153}, 0.1)`,
                border: `1px solid rgba(${rgb?.r ?? 136}, ${rgb?.g ?? 136}, ${rgb?.b ?? 153}, 0.28)`,
                boxShadow: `0 0 18px -6px ${bandGlow}`,
                marginBottom: 12,
              }}
            >
              <span className="pill-dot" />
              {label}
            </span>
            <p style={{ margin: "0 0 10px 0", fontSize: 15, color: "var(--text-body)", lineHeight: 1.6 }}>
              {aiExplanation}
            </p>
            {keyEvidence.length > 0 && (
              <ul style={{ margin: 0, padding: 0, listStyle: "none", display: "grid", gap: 6 }}>
                {keyEvidence.slice(0, 3).map((line, i) => (
                  <li key={i} style={{ display: "flex", alignItems: "flex-start", gap: 8, fontSize: 13, color: "var(--text-secondary)" }}>
                    <span style={{ marginTop: 7, width: 4, height: 4, borderRadius: 999, background: "var(--text-muted)", flex: "none" }} />
                    <span className="mono" style={{ fontSize: 12.5, lineHeight: 1.5 }}>{line}</span>
                  </li>
                ))}
              </ul>
            )}
            <div style={{ marginTop: 14, display: "flex", flexWrap: "wrap", gap: 14, fontSize: 12, color: "var(--text-muted)" }}>
              <span>Subject: <span className="mono" style={{ color: "var(--text-secondary)" }}>{data.parsed?.subject || (isLink ? "Link investigation" : "—")}</span></span>
              {data.parsed?.from_addr && <span>From: <span className="mono" style={{ color: "var(--text-secondary)" }}>{data.parsed.from_addr}</span></span>}
              <span>Report: <span className="mono" style={{ color: "var(--text-secondary)" }}>{data.email_id || emailId}</span></span>
            </div>
          </div>
        </div>
      </section>

      {/* Two-column evidence layout: left TLS + Website Security, right Campaign + On-chain */}
      <div
        style={{
          marginTop: 18,
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))",
          gap: 16,
          alignItems: "start",
        }}
      >
        <div style={{ display: "grid", gap: 16 }}>
          <SectionPanel label="TLS">
            <TlsSummary tls={tls} />
          </SectionPanel>
          <SectionPanel label="Website Security">
            <WebsiteSecuritySummary websiteSecurity={websiteSecurity} />
          </SectionPanel>
        </div>
        <div style={{ display: "grid", gap: 16 }}>
          {data.related_reports?.length ? (
            <CampaignCard related={data.related_reports} summary={data.campaign_summary} />
          ) : (
            <section className="surface" style={{ overflow: "hidden" }}>
              <div style={{ padding: "14px 18px", borderBottom: "1px solid var(--border)" }}>
                <span className="section-label">Campaign</span>
              </div>
              <div style={{ padding: "12px 18px", color: "var(--text-muted)", fontSize: 13 }}>
                No linked campaign reports found.
              </div>
            </section>
          )}
          <BlockchainRegistry reportId={data.email_id || emailId} />
        </div>
      </div>

      {/* Full detail tabs (all data preserved) */}
      <section style={{ marginTop: 28 }}>
        <div className="section-label" style={{ marginBottom: 12 }}>Full evidence</div>
        <div className="segmented" role="tablist" aria-label="Report sections" style={{ flexWrap: "wrap" }}>
          {tabs.map((tab) => (
            <button
              key={tab}
              type="button"
              role="tab"
              aria-selected={activeTab === tab}
              className={`segmented-btn ${activeTab === tab ? "active" : ""}`}
              onClick={() => setActiveTab((cur) => (cur === tab ? "" : tab))}
              style={{ height: 34, fontSize: 12 }}
            >
              {tab}
              {tab === "MITRE ATT&CK" && mitreTechniques.length > 0 && (
                <span className="num" style={{ opacity: 0.8 }}>({mitreTechniques.length})</span>
              )}
            </button>
          ))}
        </div>

        {activeTab && (
          <div key={activeTab} className="rise" style={{ marginTop: 14 }}>
            {activeTab === "Headers" && <HeaderTab headerAnalysis={data.header_analysis} />}
            {activeTab === "URLs" && <UrlTab urlAnalysis={data.url_analysis} />}
            {activeTab === "Attachments" && <AttachmentTab attachmentAnalysis={data.attachment_analysis} />}
            {activeTab === "IOCs" && <IocTab iocSummary={data.ioc_summary} threatIntelResults={threatIntelResults} />}
            {activeTab === "Link Checks" && data.checks && (
              <LinkChecksTab
                checks={data.checks}
                indicators={data.indicators || []}
                evidence={data.evidence || []}
                recommendations={data.recommendations || []}
              />
            )}
            {activeTab === "Website Security" && <WebsiteSecurityTab websiteSecurity={websiteSecurity} />}
            {activeTab === "MITRE ATT&CK" && <MitreTab mitreTechniques={mitreTechniques} />}
            {activeTab === "AI Verdict" && <AiVerdictTab aiVerdict={data.ai_verdict} />}
          </div>
        )}
      </section>
    </div>
  );
}

export default AnalysisDetail;
