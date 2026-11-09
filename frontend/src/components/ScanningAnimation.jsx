// ScanningAnimation.jsx — in-progress state for upload and link analysis.
//
// Calm and purposeful: one status line and an indeterminate progress track.
// No spinners, no scanning lasers, no decorative motion.

import Icon from "./Icon";

function ScanningAnimation({ label = "Analyzing email..." }) {
  return (
    <div
      className="flex flex-col items-center justify-center gap-5 rounded-[var(--radius-card)] border border-[var(--border)] bg-[var(--bg-secondary)] px-6 py-16 text-center"
      role="status"
      aria-live="polite"
    >
      <span className="grid h-11 w-11 place-items-center rounded-full border border-[var(--accent-border)] bg-[var(--accent-soft)] text-[var(--accent)]">
        <Icon name="scan" size={18} />
      </span>

      <div>
        <p className="text-[14px] font-medium text-[var(--text-primary)]">{label}</p>
        <p className="mt-1 text-[12px] text-[var(--text-muted)]">
          Deterministic checks run first; this can take a few seconds per URL.
        </p>
      </div>

      <div className="h-1 w-48 overflow-hidden rounded-full bg-[var(--bg-card-hover)]">
        <div className="indeterminate-bar h-full rounded-full bg-[var(--accent)]" />
      </div>
    </div>
  );
}

export default ScanningAnimation;
