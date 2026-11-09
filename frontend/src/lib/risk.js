// risk.js — the single risk vocabulary for the UI.
//
// Colour is semantic and never decorative: green = safe / Low Risk,
// amber = Suspicious, orange = High Risk, red = Confirmed Malicious.

export const CATEGORY_LABELS = {
  SAFE: "Low Risk",
  SUSPICIOUS: "Suspicious",
  HIGH: "High Risk",
  CRITICAL: "Confirmed Malicious",
};

const CATEGORY_TONES = {
  SAFE: "safe",
  SUSPICIOUS: "warn",
  HIGH: "high",
  CRITICAL: "danger",
};

const RISK_CLASS_TONES = {
  "Low Risk": "safe",
  Suspicious: "warn",
  "High Risk": "high",
  "Confirmed Malicious": "danger",
};

const SEVERITY_TONES = {
  critical: "danger",
  high: "danger",
  medium: "warn",
  low: "safe",
  info: "neutral",
};

export function categoryTone(category) {
  return CATEGORY_TONES[category] || "neutral";
}

export function categoryLabel(category) {
  return CATEGORY_LABELS[category] || category || "Unknown";
}

export function riskClassTone(riskClass) {
  return RISK_CLASS_TONES[riskClass] || "neutral";
}

export function severityTone(severity) {
  return SEVERITY_TONES[String(severity || "").toLowerCase()] || "neutral";
}

export function toneClass(tone) {
  return `tone-${tone}`;
}

const TONE_VARS = {
  safe: "var(--success)",
  warn: "var(--warning)",
  high: "var(--high)",
  danger: "var(--danger)",
  accent: "var(--accent)",
  neutral: "var(--text-muted)",
};

/** CSS colour variable for a tone — used by inline SVG strokes and glows. */
export function toneVar(tone) {
  return TONE_VARS[tone] || TONE_VARS.neutral;
}

/** Static semantic dot colour classes. */
export const TONE_TEXT = {
  safe: "text-[var(--success)]",
  warn: "text-[var(--warning)]",
  high: "text-[var(--high)]",
  danger: "text-[var(--danger)]",
  accent: "text-[var(--accent)]",
  neutral: "text-[var(--text-muted)]",
};

/** URL-level risk from the deterministic analyzer is HIGH / MEDIUM / LOW. */
export function urlRiskTone(risk) {
  const upper = String(risk || "").toUpperCase();
  if (upper === "HIGH" || upper === "CRITICAL") return "danger";
  if (upper === "MEDIUM") return "warn";
  if (upper === "LOW") return "safe";
  return "neutral";
}

export function urlRiskLabel(risk) {
  const upper = String(risk || "").toUpperCase();
  if (upper === "HIGH" || upper === "CRITICAL") return "High Risk";
  if (upper === "MEDIUM") return "Suspicious";
  if (upper === "LOW") return "Low Risk";
  return risk || "Unknown";
}
