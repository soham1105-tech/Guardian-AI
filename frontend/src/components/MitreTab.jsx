import Icon from "./Icon";

function MitreTab({ mitreTechniques }) {
  if (!mitreTechniques || mitreTechniques.length === 0) {
    return (
      <div className="surface flex flex-col items-center gap-3 px-6 py-12 text-center">
        <span className="grid h-10 w-10 place-items-center rounded-full border border-[var(--border)] bg-[var(--bg-secondary)] text-[var(--text-muted)]">
          <Icon name="layers" size={17} />
        </span>
        <div>
          <p className="text-[13.5px] font-medium">No techniques matched</p>
          <p className="mt-1 text-[12.5px] text-[var(--text-muted)]">
            Nothing in this report maps to a MITRE ATT&amp;CK technique.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-baseline justify-between gap-3">
        <h3 className="text-[15px] font-semibold">Matched techniques</h3>
        <span className="num text-[12px] text-[var(--text-muted)]">
          {mitreTechniques.length}
        </span>
      </div>

      <div className="surface divide-y divide-[var(--border)] overflow-hidden">
        {mitreTechniques.map((technique) => (
          <div
            key={technique.id}
            className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5"
          >
            <div className="min-w-0">
              <p className="text-[13px] font-medium text-[var(--text-primary)]">
                {technique.name}
              </p>
              <p className="mt-0.5 text-[12px] text-[var(--text-muted)]">
                Tactic · {technique.tactic}
              </p>
            </div>

            <a
              href={`https://attack.mitre.org/techniques/${technique.id.replace(".", "/")}/`}
              target="_blank"
              rel="noopener noreferrer"
              className={`pill ${"tone-accent"} transition-colors duration-150 hover:brightness-110`}
            >
              {technique.id}
              <Icon name="external" size={11} />
            </a>
          </div>
        ))}
      </div>
    </div>
  );
}

export default MitreTab;
