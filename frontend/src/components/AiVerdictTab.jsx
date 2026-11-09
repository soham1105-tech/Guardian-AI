import Icon from "./Icon";

function AiVerdictTab({ aiVerdict }) {
  if (!aiVerdict) return null;

  return (
    <div className="surface overflow-hidden">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[var(--border)] px-5 py-4">
        <div className="flex items-center gap-2.5">
          <span className="grid h-7 w-7 place-items-center rounded-[8px] border border-[var(--accent-border)] bg-[var(--accent-soft)] text-[var(--accent)]">
            <Icon name="activity" size={14} />
          </span>
          <span className="text-[12.5px] font-medium text-[var(--text-primary)]">
            AI threat assessment
          </span>
        </div>
        <span className="pill tone-neutral">
          <span className="pill-dot text-[var(--success)]" />
          Analyzed
        </span>
      </div>

      <div className="space-y-5 p-5 sm:p-6">
        <div>
          <span className="label">Classification</span>
          <p className="mt-1.5 text-[20px] font-semibold leading-snug tracking-[-0.02em]">
            {aiVerdict.classification}
          </p>
        </div>

        <div>
          <div className="flex items-baseline justify-between gap-3">
            <span className="label">Confidence</span>
            <span className="num text-[12.5px] font-medium text-[var(--text-secondary)]">
              {aiVerdict.confidence}%
            </span>
          </div>
          <div className="mt-2 h-1 w-full overflow-hidden rounded-full bg-[var(--bg-card-hover)]">
            <div
              className="h-full rounded-full bg-[var(--accent)] transition-[width] duration-300 ease-out"
              style={{ width: `${aiVerdict.confidence}%` }}
            />
          </div>
        </div>

        <div className="inset p-4">
          <span className="label text-[10px]">Explanation</span>
          <p className="mt-1.5 text-[13px] leading-relaxed text-[var(--text-secondary)]">
            {aiVerdict.explanation}
          </p>
        </div>

        <div className="border-t border-[var(--border)] pt-4">
          <span className="label text-[10px]">Recommended action</span>
          <div className="mt-1.5 flex items-start gap-2.5">
            <span className="mt-[2px] text-[var(--accent)]">
              <Icon name="zap" size={14} />
            </span>
            <p className="text-[13px] font-medium leading-relaxed text-[var(--text-primary)]">
              {aiVerdict.recommended_action}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default AiVerdictTab;
