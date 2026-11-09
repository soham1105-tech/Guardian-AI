import { useState } from "react";
import { uploadEmail, analyzeEmail } from "../services/api";
import { useNavigate } from "react-router-dom";
import ScanningAnimation from "./ScanningAnimation";
import Icon from "./Icon";

function UploadBox({ onAnalysisComplete }) {
  const [file, setFile] = useState(null);
  const [status, setStatus] = useState("");
  const [errorMsg, setErrorMsg] = useState("");
  const [dragActive, setDragActive] = useState(false);
  const navigate = useNavigate();

  const handleFileChange = (e) => {
    if (e.target.files[0]) {
      setFile(e.target.files[0]);
      setErrorMsg("");
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setDragActive(false);
    const dropped = e.dataTransfer.files[0];
    if (dropped) {
      setFile(dropped);
      setErrorMsg("");
    }
  };

  const handleUploadAndAnalyze = async () => {
    if (!file) return;
    try {
      setStatus("uploading");
      const uploadResult = await uploadEmail(file);
      setStatus("analyzing");
      await analyzeEmail(uploadResult.email_id);
      setStatus("");
      if (onAnalysisComplete) onAnalysisComplete();
      navigate(`/analysis/${uploadResult.email_id}`);
    } catch (err) {
      setStatus("error");
      setErrorMsg(err.response?.data?.detail || "Something went wrong during the analysis");
    }
  };

  const isBusy = status === "uploading" || status === "analyzing";

  if (isBusy) {
    return (
      <ScanningAnimation
        label={
          status === "uploading"
            ? "Uploading email payload…"
            : "Running static security analysis…"
        }
      />
    );
  }

  return (
    <div className="space-y-4">
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragActive(true);
        }}
        onDragLeave={() => setDragActive(false)}
        onDrop={handleDrop}
        className={`flex flex-col items-center gap-5 rounded-[var(--radius-card)] border border-dashed px-6 py-12 text-center transition-colors duration-200 ${
          dragActive
            ? "border-[var(--accent)] bg-[var(--accent-soft)]"
            : "border-[var(--border-strong)] bg-[var(--bg-secondary)]"
        }`}
      >
        <span className="grid h-11 w-11 place-items-center rounded-full border border-[var(--border)] bg-[var(--bg-card)] text-[var(--text-secondary)]">
          <Icon name="upload" size={18} />
        </span>

        <div className="max-w-md">
          <p className="text-[14px] font-medium text-[var(--text-primary)]">
            {file ? file.name : "Drop a raw .eml file here"}
          </p>
          <p className="mt-1.5 text-[12.5px] text-[var(--text-muted)]">
            Headers, URLs, attachments and indicators are parsed locally. Nothing is ever executed.
          </p>
        </div>

        <div className="flex flex-col items-center gap-2 sm:flex-row">
          <label className="btn btn-secondary cursor-pointer">
            <Icon name="file" size={15} />
            {file ? "Choose another file" : "Browse files"}
            <input type="file" accept=".eml" onChange={handleFileChange} className="hidden" />
          </label>

          <button
            type="button"
            onClick={handleUploadAndAnalyze}
            disabled={!file}
            className="btn btn-primary"
          >
            {status === "error" ? "Retry analysis" : "Run analysis"}
            <Icon name="arrow-right" size={15} />
          </button>
        </div>

        {!file && (
          <p className="text-[11.5px] text-[var(--text-muted)]">
            One file · .eml only · processed in memory
          </p>
        )}
      </div>

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

export default UploadBox;
