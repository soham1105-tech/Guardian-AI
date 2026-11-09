import Icon from "./Icon";
import { urlRiskLabel, urlRiskTone, toneClass } from "../lib/risk";

function UrlTab({ urlAnalysis }) {
  if (!urlAnalysis || urlAnalysis.length === 0) {
    return (
      <div className="surface flex flex-col items-center gap-3 px-6 py-12 text-center">
        <span className="grid h-10 w-10 place-items-center rounded-full border border-[var(--border)] bg-[var(--bg-secondary)] text-[var(--text-muted)]">
          <Icon name="link" size={17} />
        </span>
        <div>
          <p className="text-[13.5px] font-medium">No URLs detected</p>
          <p className="mt-1 text-[12.5px] text-[var(--text-muted)]">
            This email body and its headers contained no links.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {urlAnalysis.map((item, i) => (
        <div key={i} className="surface p-4 sm:p-5">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="flex min-w-0 items-start gap-2.5">
              <span className="mt-0.5 text-[var(--text-muted)]">
                <Icon name="link" size={14} />
              </span>
              <p className="code text-[12.5px] leading-relaxed text-[var(--text-primary)]">
                {item.url}
              </p>
            </div>
            <span className={`pill ${toneClass(urlRiskTone(item.risk))}`}>
              <span className="pill-dot" />
              {urlRiskLabel(item.risk)}
            </span>
          </div>

          {item.reasons?.length > 0 && (
            <ul className="mt-3 space-y-1.5 border-t border-[var(--border)] pt-3">
              {item.reasons.map((reason, j) => (
                <li key={j} className="flex items-start gap-2.5 text-[12.5px]">
                  <span className="mt-[8px] h-1 w-1 shrink-0 rounded-full bg-[var(--text-muted)]" />
                  <span className="leading-relaxed text-[var(--text-secondary)]">{reason}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      ))}
    </div>
  );
}

export default UrlTab;
