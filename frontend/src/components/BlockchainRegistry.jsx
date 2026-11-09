// BlockchainRegistry.jsx — on-chain integrity registry (Module 6)
//
// Only the SHA-256 hash of the report and its risk class are anchored on the
// local chain. This card lets a reviewer register the report and later prove
// the stored report has not changed since.

import { useState } from "react";
import { registerReportOnChain, verifyReportOnChain } from "../services/api";
import Icon from "./Icon";

function shortHash(value) {
  if (!value) return "—";
  return value.length > 26 ? `${value.slice(0, 14)}…${value.slice(-10)}` : value;
}

function FieldRow({ label, value, title }) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "baseline",
        justifyContent: "space-between",
        gap: 12,
        padding: "10px 0",
        borderBottom: "1px solid var(--border)",
      }}
    >
      <span className="section-label" style={{ fontSize: 10, flex: "none" }}>{label}</span>
      <span className="mono" style={{ fontSize: 12, color: "var(--text-primary)", textAlign: "right" }} title={title || undefined}>
        {value}
      </span>
    </div>
  );
}

function BlockchainRegistry({ reportId }) {
  const [registering, setRegistering] = useState(false);
  const [registration, setRegistration] = useState(null);
  const [verifying, setVerifying] = useState(false);
  const [verification, setVerification] = useState(null);
  const [error, setError] = useState("");

  if (!reportId) return null;

  const handleRegister = async () => {
    setRegistering(true);
    setError("");
    try {
      setRegistration(await registerReportOnChain(reportId));
    } catch (err) {
      setError(err.response?.data?.detail || "Registration failed");
    } finally {
      setRegistering(false);
    }
  };

  const handleVerify = async () => {
    setVerifying(true);
    setError("");
    try {
      setVerification(await verifyReportOnChain(reportId));
    } catch (err) {
      setError(err.response?.data?.detail || "Verification failed");
    } finally {
      setVerifying(false);
    }
  };

  return (
    <section className="surface" style={{ overflow: "hidden" }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 12,
          padding: "14px 18px",
          borderBottom: "1px solid var(--border)",
        }}
      >
        <span className="section-label">On-chain</span>
        <span style={{ fontSize: 11, color: "var(--text-muted)" }}>Local registry</span>
      </div>

      <div style={{ padding: "14px 18px" }}>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
          <button type="button" onClick={handleRegister} disabled={registering} className="btn btn-primary btn-sm">
            {registering ? "Registering…" : "Register"}
          </button>
          <button type="button" onClick={handleVerify} disabled={verifying} className="btn btn-secondary btn-sm">
            {verifying ? "Verifying…" : "Verify"}
          </button>
        </div>

        {registration && (
          <div style={{ marginTop: 12 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "10px 0", borderBottom: "1px solid var(--border)" }}>
              <span className="dot" style={{ color: registration.already_registered ? "var(--warning)" : "var(--success)" }} />
              <span style={{ fontSize: 13, color: "var(--text-secondary)" }}>
                {registration.already_registered ? "Already registered on this chain" : "Registered on-chain"}
              </span>
            </div>
            <FieldRow label="Transaction" value={shortHash(registration.tx_hash)} title={registration.tx_hash} />
            <FieldRow label="Contract" value={shortHash(registration.contract_address)} title={registration.contract_address} />
            <FieldRow label="Report hash" value={shortHash(registration.report_hash)} title={registration.report_hash} />
            <FieldRow label="Verdict" value={registration.verdict || "—"} />
          </div>
        )}

        {verification && (
          <div style={{ marginTop: 12 }}>
            <div style={{ display: "flex", alignItems: "flex-start", gap: 8, padding: "10px 0", borderBottom: "1px solid var(--border)" }}>
              <span className="dot" style={{ color: verification.exists ? "var(--success)" : "var(--warning)", marginTop: 6 }} />
              <span style={{ fontSize: 13, color: "var(--text-secondary)", lineHeight: 1.5 }}>
                {verification.exists
                  ? "Integrity verified — this report matches its on-chain record."
                  : "Not found on-chain — this report has not been registered on this chain."}
              </span>
            </div>
            {verification.exists && (
              <>
                <FieldRow label="Anchored" value={new Date(verification.timestamp * 1000).toLocaleString()} />
                <FieldRow label="Verdict" value={verification.verdict || "—"} />
                <FieldRow label="Submitter" value={shortHash(verification.submitter)} title={verification.submitter} />
              </>
            )}
          </div>
        )}

        {error && (
          <div style={{ marginTop: 12, display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}>
            <div style={{ display: "flex", alignItems: "flex-start", gap: 8 }}>
              <span className="dot" style={{ color: "var(--danger)", marginTop: 6 }} />
              <span style={{ fontSize: 12, color: "var(--danger)", lineHeight: 1.5 }}>{error}. Check that the Hardhat node and backend are running, then try again.</span>
            </div>
            <button type="button" onClick={() => setError("")} className="btn btn-secondary btn-sm" style={{ flex: "none" }}>Dismiss</button>
          </div>
        )}

        <p style={{ margin: "12px 0 0 0", fontSize: 11, lineHeight: 1.55, color: "var(--text-muted)" }}>
          Only the SHA-256 of the report&apos;s canonical JSON and its risk class are stored on-chain. URLs, message text, and email content never leave the database.
        </p>
      </div>
    </section>
  );
}

export default BlockchainRegistry;
