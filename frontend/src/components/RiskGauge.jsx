import { useEffect, useState } from "react";
import { categoryTone, categoryLabel, toneClass, toneVar } from "../lib/risk";

const SIZE = 168;
const STROKE = 10;
const RADIUS = (SIZE - STROKE) / 2;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;
const DURATION = 600;

function prefersReducedMotion() {
  return (
    typeof window !== "undefined" &&
    window.matchMedia?.("(prefers-reduced-motion: reduce)").matches
  );
}

function easeOutCubic(t) {
  return 1 - Math.pow(1 - t, 3);
}

function RiskGauge({ score, category }) {
  const value = Math.min(100, Math.max(0, Number(score) || 0));
  const tone = categoryTone(category);
  const label = categoryLabel(category);
  const color = toneVar(tone);

  const [displayed, setDisplayed] = useState(() => (prefersReducedMotion() ? value : 0));

  useEffect(() => {
    if (prefersReducedMotion()) {
      setDisplayed(value);
      return undefined;
    }
    let frame;
    const start = performance.now();
    const tick = (now) => {
      const progress = Math.min(1, (now - start) / DURATION);
      setDisplayed(value * easeOutCubic(progress));
      if (progress < 1) frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [value]);

  const offset = CIRCUMFERENCE - (displayed / 100) * CIRCUMFERENCE;

  return (
    <div className="flex flex-col items-center gap-4" style={{ flex: "none" }}>
      <div className="relative" style={{ width: SIZE, height: SIZE }}>
        <svg
          viewBox={`0 0 ${SIZE} ${SIZE}`}
          width={SIZE}
          height={SIZE}
          style={{ transform: "rotate(-90deg)", display: "block" }}
          role="img"
          aria-label={`Risk score ${value} out of 100, ${label}`}
        >
          <circle
            cx={SIZE / 2}
            cy={SIZE / 2}
            r={RADIUS}
            fill="none"
            stroke="var(--border)"
            strokeWidth={STROKE}
          />
          <circle
            cx={SIZE / 2}
            cy={SIZE / 2}
            r={RADIUS}
            fill="none"
            stroke={color}
            strokeWidth={STROKE}
            strokeLinecap="round"
            strokeDasharray={CIRCUMFERENCE}
            strokeDashoffset={offset}
            style={{ filter: `drop-shadow(0 0 10px ${color})` }}
          />
        </svg>
        <div
          className="absolute inset-0 flex items-center justify-center"
          style={{ flexDirection: "column" }}
        >
          <span
            className="num"
            style={{
              fontSize: 40,
              fontWeight: 600,
              lineHeight: 1,
              color,
              letterSpacing: "-0.03em",
            }}
          >
            {Math.round(displayed)}
          </span>
        </div>
      </div>
    </div>
  );
}

export default RiskGauge;
