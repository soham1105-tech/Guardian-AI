import { useEffect } from "react";
import { BrowserRouter, Routes, Route, Link, useLocation } from "react-router-dom";
import { ThemeProvider } from "./context/ThemeContext";
import ThemeToggle from "./components/ThemeToggle";
import Icon from "./components/Icon";
import Dashboard from "./pages/Dashboard";
import AnalysisDetail from "./pages/AnalysisDetail";

const DOCUMENT_TITLE = "Guardian.AI — Threat Investigation";

function Shell() {
  const location = useLocation();

  useEffect(() => {
    document.title = DOCUMENT_TITLE;
  }, []);

  return (
    <div className="flex min-h-screen flex-col" style={{ background: "var(--bg-primary)", color: "var(--text-primary)" }}>
      {/* Header: 64px, sticky, hairline bottom border */}
      <header
        className="sticky top-0 z-50"
        style={{
          height: 64,
          borderBottom: "1px solid var(--border)",
          background: "var(--panel-glass)",
          backdropFilter: "blur(16px) saturate(140%)",
          WebkitBackdropFilter: "blur(16px) saturate(140%)",
        }}
      >
        <div className="mx-auto flex h-full w-full max-w-7xl items-center justify-between px-4 sm:px-6">
          <Link to="/" className="flex items-center gap-3" style={{ textDecoration: "none" }}>
            {/* Filled shield mark: solid, cyan on dark */}
            <span
              className="grid place-items-center"
              style={{
                width: 32,
                height: 32,
                borderRadius: 8,
                background: "var(--accent)",
                color: "var(--accent-contrast)",
                flex: "none",
              }}
              aria-hidden="true"
            >
              <Icon name="shield-filled" size={16} />
            </span>
            <span className="flex flex-col justify-center">
              <span
                style={{
                  fontSize: 17,
                  fontWeight: 600,
                  lineHeight: 1,
                  letterSpacing: "-0.01em",
                  color: "var(--text-primary)",
                }}
              >
                Guardian<span style={{ color: "var(--accent)" }}>.AI</span>
              </span>
              <span
                style={{
                  marginTop: 4,
                  fontSize: 10,
                  fontWeight: 500,
                  textTransform: "uppercase",
                  letterSpacing: "0.12em",
                  lineHeight: 1,
                  color: "rgba(255,255,255,0.45)",
                }}
              >
                Threat Investigation
              </span>
            </span>
          </Link>

          <div className="flex items-center gap-3">
            <span className="hidden items-center gap-2 sm:flex" style={{ fontSize: 12, color: "var(--text-secondary)" }}>
              <span className="dot" style={{ color: "var(--success)" }} />
              Local analysis
            </span>
            <ThemeToggle />
          </div>
        </div>
      </header>

      <main key={location.pathname} className="rise mx-auto w-full max-w-7xl flex-1 px-4 py-10 sm:px-6">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/analysis/:emailId" element={<AnalysisDetail />} />
        </Routes>
      </main>

      <footer style={{ borderTop: "1px solid var(--border)" }}>
        <div
          className="mx-auto flex w-full max-w-7xl flex-col gap-1.5 px-4 py-6 sm:flex-row sm:items-center sm:justify-between sm:px-6"
          style={{ fontSize: 12, color: "var(--text-muted)" }}
        >
          <span>
            <span style={{ color: "var(--text-secondary)" }}>Guardian.AI</span> — deterministic checks with an explainable AI verdict.
          </span>
          <span>Untrusted content is never executed.</span>
        </div>
      </footer>
    </div>
  );
}

function App() {
  return (
    <ThemeProvider>
      <BrowserRouter>
        <Shell />
      </BrowserRouter>
    </ThemeProvider>
  );
}

export default App;
