import Icon from "./Icon";
import { severityTone, toneClass } from "../lib/risk";

function HeaderTab({ headerAnalysis }) {
  if (!headerAnalysis) return null;

  const rows = [
    { label: "SPF verification", value: headerAnalysis.spf },
    { label: "DKIM signature", value: headerAnalysis.dkim },
    { label: "DMARC policy", value: headerAnalysis.dmarc },
    { label: "Sender domain", value: headerAnalysis.sender_domain },
    { label: "Return-Path domain", value: headerAnalysis.return_path_domain || "—" },
    {
      label: "Domain mismatch",
      value: headerAnalysis.domain_mismatch ? "Yes" : "No",
      highlight: headerAnalysis.domain_mismatch,
    },
    {
      label: "Spoofing risk",
      value: headerAnalysis.spoofing_risk,
      tone: severityTone(headerAnalysis.spoofing_risk),
    },
  ];

  return (
    <div className="space-y-4">
      <div className="surface overflow-hidden">
        <div className="divide-y divide-[var(--border)]">
          {rows.map((row) => (
            <div
              key={row.label}
              className="flex flex-wrap items-center justify-between gap-3 px-5 py-3"
            >
              <span className="text-[12.5px] text-[var(--text-secondary)]">{row.label}</span>

              {row.tone ? (
                <span className={`pill ${toneClass(row.tone)}`}>
                  <span className="pill-dot" />
                  {row.value}
                </span>
              ) : (
                <span
                  className={`code text-[12.5px] ${
                    row.highlight
                      ? "font-medium text-[var(--danger)]"
                      : "text-[var(--text-primary)]"
                  }`}
                >
                  {row.value}
                </span>
              )}
            </div>
          ))}
        </div>
      </div>

      {headerAnalysis.reasons?.length > 0 && (
        <div className="surface p-5">
          <h3 className="label mb-3">
            Authentication findings · {headerAnalysis.reasons.length}
          </h3>
          <ul className="space-y-2.5">
            {headerAnalysis.reasons.map((reason, i) => (
              <li key={i} className="flex items-start gap-2.5">
                <span className="mt-[5px] text-[var(--warning)]">
                  <Icon name="alert" size={13} />
                </span>
                <span className="text-[12.5px] leading-relaxed text-[var(--text-secondary)]">
                  {reason}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

export default HeaderTab;
