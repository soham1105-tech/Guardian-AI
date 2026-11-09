import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getAllAnalyses, investigateLink, analyzeMessage, uploadEmail, analyzeEmail } from "../services/api";
import ScanningAnimation from "../components/ScanningAnimation";
import Icon from "../components/Icon";
import { categoryLabel, categoryTone, toneClass } from "../lib/risk";

const TABS = [
  { id: "email", label: "Scan an email", icon: "mail" },
  { id: "link", label: "Check a link", icon: "link" },
  { id: "message", label: "Paste a message", icon: "message" },
];

const EXAMPLES = {
  link: ["https://www.google.com", "http://sbi-kyc-verify.xyz/login"],
  message: ["Your KYC is pending. Verify now: http://sbi-kyc-verify.xyz/login"],
  email: [],
};

function relativeTime(dateStr) {
  if (!dateStr) return "—";
  const d = new Date(dateStr);
  if (Number.isNaN(d.getTime())) return "—";
  const diff = Date.now() - d.getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return "just now";
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const days = Math.floor(h / 24);
  if (days < 30) return `${days}d ago`;
  return d.toLocaleDateString();
}

function Dashboard() {
  const [analyses, setAnalyses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [mode, setMode] = useState("email");
  const [input, setInput] = useState("");
  const [file, setFile] = useState(null);
  const [status, setStatus] = useState("");
  const [errorMsg, setErrorMsg] = useState("");
  const [dragActive, setDragActive] = useState(false);
  const navigate = useNavigate();

  const fetchAnalyses = async () => {
    try {
      const data = await getAllAnalyses();
      setAnalyses(Array.isArray(data) ? data : []);
    } catch (err) {
      console.error("Failed to fetch analyses", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnalyses();
  }, []);

  const stats = useMemo(
    () => ({
      total: analyses.length,
      critical: analyses.filter((a) => a.risk_category === "CRITICAL").length,
      high: analyses.filter((a) => a.risk_category === "HIGH").length,
      suspicious: analyses.filter((a) => a.risk_category === "SUSPICIOUS").length,
      safe: analyses.filter((a) => a.risk_category === "SAFE").length,
    }),
    [analyses]
  );

  const statItems = [
    { label: "Investigations", value: stats.total },
    { label: "Confirmed Malicious", value: stats.critical },
    { label: "High Risk", value: stats.high },
    { label: "Suspicious", value: stats.suspicious },
    { label: "Low Risk", value: stats.safe },
  ];

  const isBusy = status === "uploading" || status === "analyzing" || status === "scanning";
  const canSubmit =
    mode === "email" ? Boolean(file) && !isBusy : input.trim().length > 0 && !isBusy;

  const handleSubmit = async (e) => {
    e?.preventDefault();
    setErrorMsg("");
    try {
      if (mode === "email") {
        if (!file) return;
        setStatus("uploading");
        const uploadResult = await uploadEmail(file);
        setStatus("analyzing");
        await analyzeEmail(uploadResult.email_id);
        setStatus("");
        fetchAnalyses();
        navigate(`/analysis/${uploadResult.email_id}`);
        return;
      }
      const target = input.trim();
      if (!target) return;
      setStatus("scanning");
      const report =
        mode === "link" ? await investigateLink(target) : await analyzeMessage(target);
      setStatus("");
      fetchAnalyses();
      navigate(`/analysis/${report.email_id}`);
    } catch (err) {
      setStatus("error");
      setErrorMsg(err.response?.data?.detail || "Investigation failed. Check that the backend is running.");
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragActive(false);
    const dropped = e.dataTransfer.files?.[0];
    if (dropped) {
      setFile(dropped);
      setErrorMsg("");
      setMode("email");
    }
  };

  const examples = EXAMPLES[mode] || [];

  if (isBusy) {
    const label =
      status === "uploading"
        ? "Uploading email payload…"
        : status === "analyzing"
        ? "Running deterministic checks…"
        : "Investigating…";
    return (
      <div className="mx-auto" style={{ maxWidth: 880 }}>
        <ScanningAnimation label={label} />
      </div>
    );
  }

  return (
    <div className="mx-auto" style={{ maxWidth: 880 }}>
      {/* 1. Hero */}
      <section style={{ textAlign: "center", paddingTop: 24, paddingBottom: 8 }}>
        <h1 className="hero-headline">Check before you click.</h1>
        <p
          style={{
            marginTop: 16,
            fontSize: 15,
            fontWeight: 400,
            color: "rgba(255,255,255,0.6)",
            maxWidth: 720,
            marginLeft: "auto",
            marginRight: "auto",
            lineHeight: 1.6,
          }}
        >
          Submit a suspicious email or check a link. Every verdict is built from deterministic checks, with an AI layer that explains the result.
        </p>
      </section>

      {/* 2. Command bar */}
      <section style={{ marginTop: 36 }}>
        {mode === "email" ? (
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setDragActive(true);
            }}
            onDragLeave={() => setDragActive(false)}
            onDrop={handleDrop}
            className="command-bar"
            style={{
              borderColor: dragActive ? "var(--accent)" : undefined,
              boxShadow: dragActive ? "var(--accent-glow)" : undefined,
              cursor: "default",
            }}
          >
            <span className="command-bar-icon" aria-hidden="true">
              <Icon name="mail" size={18} />
            </span>
            <div
              style={{
                flex: 1,
                minWidth: 0,
                display: "flex",
                alignItems: "center",
                fontSize: 16,
                color: file ? "var(--text-primary)" : "var(--text-muted)",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              {file ? file.name : "Drop a .eml file here, or browse to scan an email"}
            </div>
            <label
              className="btn btn-secondary btn-sm"
              style={{ cursor: "pointer", height: 36, borderRadius: 10, flex: "none" }}
            >
              Browse
              <input
                type="file"
                accept=".eml"
                onChange={(e) => {
                  const picked = e.target.files?.[0];
                  if (picked) {
                    setFile(picked);
                    setErrorMsg("");
                  }
                }}
                style={{ display: "none" }}
              />
            </label>
            <button
              type="button"
              onClick={handleSubmit}
              disabled={!file}
              className="command-bar-btn"
            >
              Investigate
            </button>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="command-bar">
            <span className="command-bar-icon" aria-hidden="true">
              <Icon name={mode === "link" ? "link" : "message"} size={18} />
            </span>
            <input
              type="text"
              className="command-bar-input"
              value={input}
              onChange={(e) => {
                setInput(e.target.value);
                setErrorMsg("");
              }}
              placeholder={
                mode === "link"
                  ? "https://example.com/login or sbi-kyc-verify.xyz/login"
                  : "Paste a suspicious message, SMS, or chat text"
              }
              aria-label={mode === "link" ? "URL or domain to investigate" : "Message to investigate"}
              spellCheck={false}
              autoComplete="off"
              inputMode={mode === "link" ? "url" : "text"}
            />
            <button type="submit" disabled={!input.trim()} className="command-bar-btn">
              Investigate
            </button>
          </form>
        )}

        {errorMsg && (
          <div
            role="alert"
            style={{
              marginTop: 12,
              display: "flex",
              alignItems: "flex-start",
              gap: 10,
              padding: "10px 14px",
              borderRadius: 12,
              border: "1px solid var(--danger-border)",
              background: "var(--danger-bg)",
              color: "var(--danger)",
              fontSize: 13,
            }}
          >
            <span style={{ marginTop: 1, flex: "none" }}>
              <Icon name="alert" size={14} />
            </span>
            <span style={{ flex: 1 }}>{errorMsg}</span>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={handleSubmit}
              disabled={!canSubmit}
              style={{ flex: "none", height: 28, borderRadius: 8, padding: "0 10px", fontSize: 12 }}
            >
              Retry
            </button>
          </div>
        )}
      </section>

      {/* 3. Segmented control */}
      <section style={{ marginTop: 16 }}>
        <div className="segmented" role="tablist" aria-label="Investigation mode">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={mode === tab.id}
              className={`segmented-btn ${mode === tab.id ? "active" : ""}`}
              onClick={() => {
                setMode(tab.id);
                setErrorMsg("");
              }}
            >
              <Icon name={tab.icon} size={14} />
              {tab.label}
            </button>
          ))}
        </div>
      </section>

      {/* 4. Example chips */}
      {examples.length > 0 && (
        <section style={{ marginTop: 14, display: "flex", flexWrap: "wrap", gap: 8 }}>
          {examples.map((ex) => (
            <button
              key={ex}
              type="button"
              className="chip"
              onClick={() => {
                if (mode === "message") setInput(ex);
                else setInput(ex);
                setErrorMsg("");
              }}
              title={ex}
            >
              {ex.length > 60 ? `${ex.slice(0, 60)}…` : ex}
            </button>
          ))}
        </section>
      )}

      {/* 5. Stats strip */}
      <section style={{ marginTop: 40 }}>
        <div className="stats-strip">
          {statItems.map((item) => (
            <div key={item.label} className="stats-strip-item">
              <div className="stats-strip-label">{item.label}</div>
              <div className="stats-strip-value">{item.value}</div>
            </div>
          ))}
        </div>
      </section>

      {/* 6. Recent investigations table */}
      <section style={{ marginTop: 40, paddingBottom: 24 }}>
        <div className="section-label" style={{ marginBottom: 14 }}>
          Recent investigations
        </div>

        {loading ? (
          <div style={{ borderTop: "1px solid var(--border)" }}>
            {[0, 1, 2].map((i) => (
              <div
                key={i}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 16,
                  padding: "14px 0",
                  borderBottom: "1px solid var(--border)",
                }}
              >
                <div style={{ height: 12, width: 220, borderRadius: 999, background: "var(--bg-card-hover)" }} />
                <div style={{ height: 12, width: 48, borderRadius: 999, background: "var(--bg-card-hover)", marginLeft: "auto" }} />
              </div>
            ))}
          </div>
        ) : analyses.length === 0 ? (
          <div
            style={{
              borderTop: "1px solid var(--border)",
              padding: "28px 0",
              color: "var(--text-muted)",
              fontSize: 14,
              display: "flex",
              alignItems: "center",
              gap: 14,
              flexWrap: "wrap",
            }}
          >
            <span aria-hidden="true" style={{ color: "var(--text-muted)", flex: "none" }}>
              <Icon name="shield" size={18} />
            </span>
            <span style={{ flex: "1 1 220px" }}>No investigations yet. Run your first check to create a report.</span>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => { setMode("link"); setErrorMsg(""); window.scrollTo({ top: 0, behavior: "smooth" }); }}
              style={{ flex: "none" }}
            >
              Check a link
            </button>
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: "46%" }}>Verdict</th>
                  <th>Investigation</th>
                  <th style={{ width: 100 }}>Risk score</th>
                  <th style={{ width: 120, textAlign: "right" }}>Time</th>
                </tr>
              </thead>
              <tbody>
                {analyses.map((a) => {
                  const tone = categoryTone(a.risk_category);
                  const label = categoryLabel(a.risk_category);
                  const score = a.risk_score ?? a.score ?? "—";
                  const text = a.filename || a.subject || a.input_text || a.email_id || "Investigation";
                  return (
                    <tr
                      key={a.email_id}
                      className="clickable"
                      onClick={() => navigate(`/analysis/${a.email_id}`)}
                      tabIndex={0}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === " ") navigate(`/analysis/${a.email_id}`);
                      }}
                    >
                      <td>
                        <span className={`pill ${toneClass(tone)}`}>
                          <span className="pill-dot" />
                          {label}
                        </span>
                      </td>
                      <td>
                        <span
                          className="mono"
                          title={text}
                          style={{
                            display: "block",
                            maxWidth: 420,
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                            color: "var(--text-body)",
                          }}
                        >
                          {text}
                        </span>
                      </td>
                      <td>
                        <span className="num" style={{ color: "var(--text-primary)", fontWeight: 500 }}>
                          {score}
                        </span>
                      </td>
                      <td style={{ textAlign: "right", color: "var(--text-muted)", fontSize: 13 }}>
                        {relativeTime(a.created_at)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

export default Dashboard;
