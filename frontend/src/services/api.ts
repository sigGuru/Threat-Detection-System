import axios from 'axios';
import type { BinaryAnalysisResult, ReportAnalysisResult, UnifiedAnalysis } from '../types/analysis';

// Use relative URL so Vite proxy forwards to backend, with fallback for direct access
const API_BASE = '/api';

export const checkHealth = async (): Promise<{ status: string; service: string }> => {
  const res = await axios.get(`${API_BASE}/health`, { timeout: 3000 });
  return res.data;
};

export const uploadBinary = async (file: File): Promise<BinaryAnalysisResult> => {
  const formData = new FormData();
  formData.append('file', file);

  const res = await axios.post<BinaryAnalysisResult>(`${API_BASE}/upload`, formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 60000,
  });

  return res.data;
};

export const uploadReport = async (file: File): Promise<ReportAnalysisResult> => {
  const formData = new FormData();
  formData.append('file', file);

  const res = await axios.post<ReportAnalysisResult>(`${API_BASE}/analyze-report`, formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 30000,
  });

  return res.data;
};

export const autoAnalyze = async (file: File): Promise<UnifiedAnalysis> => {
  const name = file.name.toLowerCase();
  if (name.endsWith('.json')) {
    const data = await uploadReport(file);
    return { type: 'report', data };
  } else {
    const data = await uploadBinary(file);
    return { type: 'binary', data };
  }
};
