// CampaignCard.jsx — "Part of a campaign" (Module 4)
//
// Related reports come from deterministic exact-indicator matching on the
// backend. This component only renders them; it never infers a link and shows
// nothing when the list is empty.

import { Link } from "react-router-dom";
import Icon from "./Icon";
import { riskClassTone, toneClass } from "../lib/risk";

const TYPE_ICONS = { url: "link", message: "message", email: "mail" };

function shortInput(text, limit = 90) {
  const value = (text || "").replace(/\s+/g, " ").trim();
  if (value.length <= limit) return value;
  return `${value.slice(0, limit)}…`;
}

function CampaignCard({ related, summary }) {
  if (!related || related.length === 0) return null;

  return (
    <section className="surface" style={{ overflow: "hidden" }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 12,
          padding: "14px 18px",
          borderBottom: "1px solid var(--border)",
        }}
      >
        <span className="section-label">Campaign</span>
        <span className="num" style={{ fontSize: 11, color: "var(--text-muted)" }}>
          {related.length} linked
        </span>
      </div>

      <div style={{ padding: "0 18px" }}>
        {summary && (
          <div
            style={{
              padding: "12px 0",
              borderBottom: "1px solid var(--border)",
              fontSize: 13,
              color: "var(--text-secondary)",
              lineHeight: 1.55,
            }}
          >
            {summary}
          </div>
        )}

        {related.map((entry) => (
          <Link
            key={entry.id}
            to={`/analysis/${entry.id}`}
            style={{
              display: "flex",
              alignItems: "flex-start",
              justifyContent: "space-between",
              gap: 14,
              padding: "12px 0",
              borderBottom: "1px solid var(--border)",
              textDecoration: "none",
              color: "inherit",
            }}
          >
            <div style={{ minWidth: 0, flex: 1 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <span style={{ color: "var(--text-muted)", flex: "none" }}>
                  <Icon name={TYPE_ICONS[entry.input_type] || "file"} size={14} />
                </span>
                <span
                  className="mono"
                  style={{
                    fontSize: 13,
                    color: "var(--text-primary)",
                    overflow: "hidden",
                    textOverflow: "ellipsis",
                    whiteSpace: "nowrap",
                  }}
                  title={entry.input_text || entry.id}
                >
                  {shortInput(entry.input_text) || entry.id}
                </span>
              </div>
              {entry.shared_indicator && (
                <div style={{ marginTop: 6, display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: "var(--text-secondary)" }}>
                  <span className="dot" style={{ color: "var(--warning)" }} />
                  <span>{entry.shared_indicator}</span>
                </div>
              )}
              <div style={{ marginTop: 4, fontSize: 11, color: "var(--text-muted)" }}>
                {entry.created_at}
              </div>
            </div>
            <span className={`pill ${toneClass(riskClassTone(entry.risk_class))}`} style={{ flex: "none" }}>
              <span className="pill-dot" />
              {entry.risk_class || "Unknown"}
            </span>
          </Link>
        ))}
      </div>
    </section>
  );
}

export default CampaignCard;
