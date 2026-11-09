import { useState } from "react";
import ThreatIntelBadge from "./ThreatIntelBadge";
import Icon from "./Icon";

function IocTab({ iocSummary, threatIntelResults }) {
  const [copied, setCopied] = useState(false);

  if (!iocSummary) return null;

  const results = threatIntelResults || {};

  const sections = [
    { label: "Domains", items: iocSummary.domains },
    { label: "IP addresses", items: iocSummary.ips },
    { label: "URLs", items: iocSummary.urls },
    { label: "Email addresses", items: iocSummary.emails },
    { label: "Hashes", items: iocSummary.hashes },
  ];

  const copyAll = () => {
    const text = sections
      .filter((s) => s.items?.length > 0)
      .map((s) => `[${s.label}]\n${s.items.join("\n")}`)
      .join("\n\n");
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h3 className="text-[15px] font-semibold">Indicators of compromise</h3>
          <p className="mt-1 text-[12.5px] text-[var(--text-muted)]">
            Reputation is checked for domains, IPs, URLs and hashes only.
          </p>
        </div>
        <button type="button" onClick={copyAll} className="btn btn-secondary btn-sm">
          <Icon name={copied ? "check" : "copy"} size={13} />
          {copied ? "Copied" : "Copy all"}
        </button>
      </div>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        {sections.map((section) => (
          <div key={section.label} className="surface flex flex-col p-4">
            <div className="flex items-center justify-between gap-3">
              <span className="text-[12.5px] font-medium text-[var(--text-primary)]">
                {section.label}
              </span>
              <span className="num text-[11.5px] text-[var(--text-muted)]">
                {section.items?.length || 0}
              </span>
            </div>

            {!section.items || section.items.length === 0 ? (
              <p className="mt-3 text-[12px] text-[var(--text-muted)]">
                No indicators extracted
              </p>
            ) : (
              <ul className="mt-3 max-h-44 space-y-1.5 overflow-y-auto pr-1">
                {section.items.map((item, i) => (
                  <li
                    key={i}
                    className="inset flex items-center justify-between gap-3 px-2.5 py-1.5"
                  >
                    <span className="code min-w-0 flex-1 text-[11.5px] text-[var(--text-secondary)]">
                      {item}
                    </span>
                    {section.label === "Email addresses" ? (
                      <span className="shrink-0 text-[10.5px] text-[var(--text-muted)]">
                        Not checked
                      </span>
                    ) : (
                      <div className="shrink-0">
                        <ThreatIntelBadge verdicts={results[item]} />
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

export default IocTab;
