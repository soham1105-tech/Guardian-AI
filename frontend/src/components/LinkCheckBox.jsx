// LinkCheckBox.jsx — investigate a single URL/domain without an email
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { investigateLink } from "../services/api";
import ScanningAnimation from "./ScanningAnimation";
import Icon from "./Icon";

const EXAMPLES = ["https://www.google.com", "http://sbi-kyc-verify.xyz/login"];

function LinkCheckBox({ onAnalysisComplete }) {
  const [url, setUrl] = useState("");
  const [status, setStatus] = useState("");
  const [errorMsg, setErrorMsg] = useState("");
  const navigate = useNavigate();

  const isBusy = status === "scanning";

  const handleInvestigate = async (event) => {
    event?.preventDefault();
    const target = url.trim();
    if (!target) return;

    try {
      setStatus("scanning");
      setErrorMsg("");
      const report = await investigateLink(target);
      setStatus("");
      if (onAnalysisComplete) onAnalysisComplete();
      navigate(`/analysis/${report.email_id}`);
    } catch (err) {
      setStatus("error");
      setErrorMsg(err.response?.data?.detail || "Something went wrong during the investigation");
    }
  };

  if (isBusy) {
    return (
      <ScanningAnimation label="Resolving DNS, following redirects and checking reputation…" />
    );
  }

  return (
    <div className="space-y-4">
      <form onSubmit={handleInvestigate} className="space-y-5">
        <div className="flex flex-col gap-2 sm:flex-row">
          <div className="relative flex-1">
            <span className="pointer-events-none absolute left-3.5 top-1/2 -translate-y-1/2 text-[var(--text-muted)]">
              <Icon name="link" size={15} />
            </span>
            <input
              type="text"
              inputMode="url"
              spellCheck={false}
              autoComplete="off"
              value={url}
              onChange={(e) => {
                setUrl(e.target.value);
                setErrorMsg("");
              }}
              placeholder="https://example.com/login or sbi-kyc-verify.xyz/login"
              aria-label="URL or domain to investigate"
              className="field pl-10"
            />
          </div>
          <button type="submit" disabled={!url.trim()} className="btn btn-primary shrink-0">
            Investigate
            <Icon name="arrow-right" size={15} />
          </button>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[11.5px] text-[var(--text-muted)]">Examples</span>
          {EXAMPLES.map((example) => (
            <button
              key={example}
              type="button"
              onClick={() => {
                setUrl(example);
                setErrorMsg("");
              }}
              className="rounded-full border border-[var(--border)] px-2.5 py-1 text-[11.5px] text-[var(--text-secondary)] transition-colors duration-150 hover:border-[var(--accent-border)] hover:text-[var(--accent)]"
            >
              {example}
            </button>
          ))}
        </div>

        <p className="max-w-2xl text-[11.5px] leading-relaxed text-[var(--text-muted)]">
          Private, loopback and metadata targets are rejected. Pages are fetched read-only with a
          5-second timeout and a 1 MB cap — scripts are never executed and files are never
          downloaded.
        </p>
      </form>

      {errorMsg && (
        <div className="flex items-start gap-2.5 rounded-[var(--radius-control)] border border-[var(--danger-border)] bg-[var(--danger-bg)] px-3.5 py-3">
          <span className="mt-0.5 text-[var(--danger)]">
            <Icon name="alert" size={15} />
          </span>
          <p className="text-[12.5px] leading-relaxed text-[var(--danger)]">{errorMsg}</p>
        </div>
      )}
    </div>
  );
}

export default LinkCheckBox;
