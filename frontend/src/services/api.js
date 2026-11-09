import axios from "axios";

// VITE_API_URL is the backend origin (e.g. https://api.example.com or the local backend).
// Falls back to local dev when unset.
const _devHost = "localhost";
const _devPort = "8000";
const API_BASE = (import.meta.env.VITE_API_URL || `http://${_devHost}:${_devPort}`).replace(/\/$/, "");
const API_BASE_URL = API_BASE.endsWith("/api") ? API_BASE : `${API_BASE}/api`;

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
});

// --- Upload email ---
export const uploadEmail = async (file) => {
  const formData = new FormData();
  formData.append("file", file);

  const response = await api.post("/upload", formData, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  return response.data; // { email_id, filename, status }
};

// --- Trigger analysis ---
export const analyzeEmail = async (emailId) => {
  const response = await api.post(`/analyze/${emailId}`);
  return response.data; // full analysis JSON
};

// --- Investigate a standalone URL/domain (no email upload) ---
export const investigateLink = async (url) => {
  const response = await api.post("/investigate", { url });
  return response.data; // full link report, same shape as an email analysis
};

// --- On-chain integrity registry (Module 6) ---
export const registerReportOnChain = async (reportId) => {
  const response = await api.post(`/reports/${reportId}/register`);
  return response.data; // { tx_hash, contract_address, report_hash, ... }
};

export const verifyReportOnChain = async (reportId) => {
  const response = await api.get(`/reports/${reportId}/verify`);
  return response.data; // { exists, timestamp, submitter, verdict }
};

// --- Get all past analyses (for dashboard list) ---
export const getAllAnalyses = async () => {
  const response = await api.get("/analyses");
  return response.data;
};

// --- Get single analysis by email_id (for detail page) ---
export const getAnalysisById = async (emailId) => {
  const response = await api.get(`/analyses/${emailId}`);
  return response.data;
};

// --- Analyze a pasted message / SMS / chat transcript ---
export const analyzeMessage = async (text) => {
  const response = await api.post("/analyze-message", { text });
  return response.data; // full report, same shape as an email analysis
};

export default api;