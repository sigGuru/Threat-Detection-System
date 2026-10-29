import React, { useState } from 'react';
import {
  UploadCloud,
  FileCode2,
  FileText,
  AlertTriangle,
  Loader2,
  Sparkles,
  CheckCircle2,
  ShieldAlert,
  ArrowRight
} from 'lucide-react';
import { uploadBinary, uploadReport } from '../services/api';
import type { UnifiedAnalysis } from '../types/analysis';

interface FileUploadProps {
  onAnalysisComplete: (result: UnifiedAnalysis) => void;
  backendOnline: boolean;
}

export const FileUpload: React.FC<FileUploadProps> = ({ onAnalysisComplete, backendOnline }) => {
  const [selectedMode, setSelectedMode] = useState<'auto' | 'binary' | 'report'>('auto');
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const [loadingStep, setLoadingStep] = useState<string>('Initializing analysis...');

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setError(null);
    }
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFile(e.dataTransfer.files[0]);
      setError(null);
    }
  };

  const handleUpload = async () => {
    if (!file) {
      setError('Please select a file to analyze.');
      return;
    }

    if (file.size > 100 * 1024 * 1024) {
      setError(`File size (${(file.size / (1024 * 1024)).toFixed(1)} MB) exceeds the maximum allowed limit of 100 MB.`);
      return;
    }

    setUploading(true);
    setError(null);

    const name = file.name.toLowerCase();
    const isJson = name.endsWith('.json');
    const isBinary = name.endsWith('.exe') || name.endsWith('.dll') || name.endsWith('.sys');

    try {
      if (selectedMode === 'report' || (selectedMode === 'auto' && isJson)) {
        setLoadingStep('Ingesting sandbox report & behavioral telemetry...');
        const data = await uploadReport(file);
        setLoadingStep('Evaluating ML risk and heuristics...');
        onAnalysisComplete({ type: 'report', data });
      } else if (selectedMode === 'binary' || (selectedMode === 'auto' && isBinary)) {
        setLoadingStep('Parsing PE headers & section tables...');
        const data = await uploadBinary(file);
        setLoadingStep('Running YARA pattern matching...');
        onAnalysisComplete({ type: 'binary', data });
      } else {
        // Fallback: attempt auto-detection based on MIME or extension
        if (isJson) {
          const data = await uploadReport(file);
          onAnalysisComplete({ type: 'report', data });
        } else {
          const data = await uploadBinary(file);
          onAnalysisComplete({ type: 'binary', data });
        }
      }
      setFile(null);
    } catch (err: any) {
      const resp = err.response;
      let msg = 'Analysis request failed. Please check backend connection.';
      if (resp?.status === 413) {
        msg = resp.data?.message || 'File size exceeds maximum upload limit (100 MB). Please choose a smaller file.';
      } else if (resp?.data?.message) {
        msg = resp.data.message;
      } else if (resp?.data?.error) {
        msg = resp.data.error;
      } else if (err.message) {
        msg = err.message;
      }
      setError(msg);
    } finally {
      setUploading(false);
    }
  };

  const handleLoadSampleReport = async () => {
    setUploading(true);
    setError(null);
    setLoadingStep('Loading built-in sample_report.json demo...');

    try {
      const response = await fetch('/sample_report.json');
      if (!response.ok) {
        throw new Error('sample_report.json is not available via web server. Please browse and select it from project root.');
      }
      const jsonBlob = await response.blob();
      const sampleFile = new File([jsonBlob], 'sample_report.json', { type: 'application/json' });
      const data = await uploadReport(sampleFile);
      onAnalysisComplete({ type: 'report', data });
    } catch (err: any) {
      setError(err.message || 'Failed to load sample report.');
    } finally {
      setUploading(false);
    }
  };

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  return (
    <div className="w-full max-w-4xl mx-auto space-y-6">
      {/* Mode selection pills */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-slate-900/80 p-2 rounded-xl border border-slate-800 backdrop-blur-md">
        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={() => setSelectedMode('auto')}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2 ${
              selectedMode === 'auto'
                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <Sparkles className="w-4 h-4" />
            Smart Auto-Detect
          </button>
          <button
            type="button"
            onClick={() => setSelectedMode('binary')}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2 ${
              selectedMode === 'binary'
                ? 'bg-blue-500/20 text-blue-400 border border-blue-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <FileCode2 className="w-4 h-4" />
            Binary PE (EXE, DLL)
          </button>
          <button
            type="button"
            onClick={() => setSelectedMode('report')}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-all flex items-center gap-2 ${
              selectedMode === 'report'
                ? 'bg-purple-500/20 text-purple-400 border border-purple-500/40 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
            }`}
          >
            <FileText className="w-4 h-4" />
            Sandbox Report (JSON)
          </button>
        </div>

        {/* Quick sample trigger */}
        <button
          type="button"
          onClick={handleLoadSampleReport}
          disabled={uploading || !backendOnline}
          className="text-xs px-3 py-1.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/20 transition-all flex items-center gap-1.5 disabled:opacity-50 disabled:cursor-not-allowed"
          title="Instantly analyze sample_report.json"
        >
          <Sparkles className="w-3.5 h-3.5 text-emerald-400" />
          Load Demo Report
        </button>
      </div>

      {/* Main Drag & Drop Zone */}
      <div
        className={`relative border-2 border-dashed rounded-2xl p-10 text-center transition-all duration-300 backdrop-blur-xl ${
          dragActive
            ? 'border-cyan-400 bg-cyan-950/20 shadow-2xl glow-cyan scale-[1.01]'
            : 'border-slate-800 hover:border-slate-700 bg-slate-900/50'
        }`}
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
      >
        <div className="mx-auto w-16 h-16 rounded-2xl bg-gradient-to-tr from-cyan-500/20 via-blue-500/20 to-purple-500/20 border border-slate-700/60 flex items-center justify-center mb-5 text-cyan-400">
          <UploadCloud className="w-8 h-8" />
        </div>

        <h3 className="text-xl font-bold text-slate-100 mb-1">
          Drop your file here or{' '}
          <label htmlFor="file-upload" className="text-cyan-400 hover:text-cyan-300 cursor-pointer underline underline-offset-4">
            browse disk
          </label>
        </h3>
        <input
          id="file-upload"
          type="file"
          className="sr-only"
          onChange={handleFileChange}
          accept={
            selectedMode === 'binary'
              ? '.exe,.dll,.sys'
              : selectedMode === 'report'
              ? '.json'
              : '.exe,.dll,.sys,.json'
          }
        />

        <p className="text-sm text-slate-400 mt-2">
          {selectedMode === 'binary' && 'Supports PE format binaries (.exe, .dll, .sys) up to 10 MB'}
          {selectedMode === 'report' && 'Supports Cuckoo / sandbox behavioral telemetry (.json) up to 10 MB'}
          {selectedMode === 'auto' && 'Supports both Portable Executables (.exe, .dll) and Sandbox Reports (.json)'}
        </p>

        {/* Selected file card */}
        {file && (
          <div className="mt-6 max-w-md mx-auto p-4 rounded-xl bg-slate-800/80 border border-slate-700 flex items-center justify-between text-left shadow-lg">
            <div className="flex items-center gap-3 overflow-hidden">
              <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 flex-shrink-0">
                {file.name.endsWith('.json') ? <FileText className="w-5 h-5" /> : <FileCode2 className="w-5 h-5" />}
              </div>
              <div className="overflow-hidden">
                <p className="text-sm font-semibold text-slate-100 truncate">{file.name}</p>
                <p className="text-xs text-slate-400">{formatFileSize(file.size)}</p>
              </div>
            </div>
            <button
              type="button"
              onClick={() => setFile(null)}
              className="text-xs text-slate-400 hover:text-rose-400 px-2 py-1 transition-colors"
            >
              Clear
            </button>
          </div>
        )}
      </div>

      {/* Error alert */}
      {error && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-800/60 text-rose-300 flex items-start gap-3 shadow-lg">
          <AlertTriangle className="w-5 h-5 text-rose-400 flex-shrink-0 mt-0.5" />
          <div className="text-sm">
            <span className="font-semibold">Analysis Failed: </span>
            {error}
          </div>
        </div>
      )}

      {/* Action CTA */}
      <div className="flex flex-col sm:flex-row items-center gap-3">
        <button
          type="button"
          onClick={handleUpload}
          disabled={!file || uploading || !backendOnline}
          className={`flex-1 w-full py-3.5 px-6 rounded-xl font-semibold text-sm transition-all duration-200 flex items-center justify-center gap-2 shadow-xl ${
            !file || uploading || !backendOnline
              ? 'bg-slate-800/60 text-slate-500 border border-slate-800 cursor-not-allowed'
              : 'bg-gradient-to-r from-cyan-500 to-blue-600 text-slate-950 hover:brightness-110 active:scale-[0.99] glow-cyan'
          }`}
        >
          {uploading ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin text-slate-950" />
              <span>{loadingStep}</span>
            </>
          ) : (
            <>
              <span>Run Deep Threat Analysis</span>
              <ArrowRight className="w-4 h-4" />
            </>
          )}
        </button>
      </div>

      {/* Feature capabilities grid */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-4">
        <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800/60">
          <div className="flex items-center gap-2 text-cyan-400 text-xs font-semibold uppercase tracking-wider mb-1">
            <CheckCircle2 className="w-3.5 h-3.5" />
            Static PE Analysis
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Machine architectures, subsystem specs, entropy scores, and section characteristics.
          </p>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800/60">
          <div className="flex items-center gap-2 text-rose-400 text-xs font-semibold uppercase tracking-wider mb-1">
            <ShieldAlert className="w-3.5 h-3.5" />
            YARA Rules & Signatures
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Pattern-matched malware markers, dropper names, and automated signature scanning.
          </p>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800/60">
          <div className="flex items-center gap-2 text-purple-400 text-xs font-semibold uppercase tracking-wider mb-1">
            <Sparkles className="w-3.5 h-3.5" />
            Behavioral Telemetry
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            Process injections, dropped artifacts, registry mutations, C2 networking, and trust scores.
          </p>
        </div>
      </div>
    </div>
  );
};
