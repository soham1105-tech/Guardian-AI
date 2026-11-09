import { toneClass } from "../lib/risk";

function ThreatIntelBadge({ verdicts }) {
  if (!verdicts || verdicts.length === 0) {
    return (
      <span className={`pill ${toneClass("neutral")}`} title="No reputation check ran for this indicator">
        <span className="pill-dot" />
        Not checked
      </span>
    );
  }

  const checkedVerdicts = verdicts.filter((v) => v.checked);
  const maliciousVerdicts = checkedVerdicts.filter((v) => v.malicious);

  if (maliciousVerdicts.length > 0) {
    const topConfidence = Math.max(...maliciousVerdicts.map((v) => v.confidence));
    return (
      <span
        className={`pill ${toneClass("danger")}`}
        title={maliciousVerdicts.map((v) => `${v.provider}: ${v.detail}`).join("\n")}
      >
        <span className="pill-dot" />
        {maliciousVerdicts.length} vendor{maliciousVerdicts.length > 1 ? "s" : ""} flagged ·{" "}
        {topConfidence}%
      </span>
    );
  }

  if (checkedVerdicts.length > 0) {
    return (
      <span
        className={`pill ${toneClass("safe")}`}
        title={checkedVerdicts.map((v) => `${v.provider}: ${v.detail}`).join("\n")}
      >
        <span className="pill-dot" />
        Clean
      </span>
    );
  }

  // All providers failed/unavailable — nothing was actually verified
  return (
    <span
      className={`pill ${toneClass("neutral")}`}
      title={verdicts.map((v) => `${v.provider}: ${v.detail}`).join("\n")}
    >
      <span className="pill-dot" />
      Unverified
    </span>
  );
}

export default ThreatIntelBadge;
