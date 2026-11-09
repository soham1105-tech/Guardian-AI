import Icon from "./Icon";
import { urlRiskLabel, urlRiskTone, toneClass } from "../lib/risk";

function AttachmentTab({ attachmentAnalysis }) {
  if (!attachmentAnalysis || attachmentAnalysis.length === 0) {
    return (
      <div className="surface flex flex-col items-center gap-3 px-6 py-12 text-center">
        <span className="grid h-10 w-10 place-items-center rounded-full border border-[var(--border)] bg-[var(--bg-secondary)] text-[var(--text-muted)]">
          <Icon name="paperclip" size={17} />
        </span>
        <div>
          <p className="text-[13.5px] font-medium">No attachments</p>
          <p className="mt-1 text-[12.5px] text-[var(--text-muted)]">
            This email carried no attached files.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {attachmentAnalysis.map((att, i) => (
        <div key={i} className="surface p-4 sm:p-5">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="flex min-w-0 items-center gap-3">
              <span className="grid h-9 w-9 shrink-0 place-items-center rounded-[10px] border border-[var(--border)] bg-[var(--bg-secondary)] text-[var(--text-secondary)]">
                <Icon name="paperclip" size={16} />
              </span>
              <div className="min-w-0">
                <p className="truncate text-[13.5px] font-medium text-[var(--text-primary)]">
                  {att.filename}
                </p>
                <p className="num mt-0.5 text-[11.5px] text-[var(--text-muted)]">
                  {(att.size_bytes / 1024).toFixed(1)} KB · {att.size_bytes} bytes
                </p>
              </div>
            </div>

            <span className={`pill ${toneClass(urlRiskTone(att.risk))}`}>
              <span className="pill-dot" />
              {urlRiskLabel(att.risk)}
            </span>
          </div>

          <div className="inset mt-3 flex items-center gap-3 px-3 py-2">
            <span className="label shrink-0 text-[9.5px]">SHA-256</span>
            <span className="code min-w-0 flex-1 select-all text-[11.5px] text-[var(--text-secondary)]">
              {att.sha256}
            </span>
          </div>

          {att.reasons?.length > 0 && (
            <ul className="mt-3 space-y-1.5 border-t border-[var(--border)] pt-3">
              {att.reasons.map((reason, j) => (
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

export default AttachmentTab;
