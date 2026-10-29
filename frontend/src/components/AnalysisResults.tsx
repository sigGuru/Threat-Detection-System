import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  ArrowLeft,
  Copy,
  Check,
  Cpu,
  Layers,
  Network,
  Activity,
  Terminal,
  FileCode2,
  Boxes,
  Lock,
  Download
} from 'lucide-react';
import type { UnifiedAnalysis, BinaryAnalysisResult, ReportAnalysisResult } from '../types/analysis';

interface AnalysisResultsProps {
  result: UnifiedAnalysis;
  onReset: () => void;
}

export const AnalysisResults: React.FC<AnalysisResultsProps> = ({ result, onReset }) => {
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [copied, setCopied] = useState<boolean>(false);

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(result.data, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleExportJson = () => {
    const filename = `${result.data.filename || 'analysis'}-report.json`;
    const blob = new Blob([JSON.stringify(result.data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="w-full max-w-6xl mx-auto space-y-6">
      {/* Top action navigation */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-slate-900/80 p-4 rounded-2xl border border-slate-800 backdrop-blur-xl">
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={onReset}
            className="p-2 rounded-xl bg-slate-800 text-slate-300 hover:text-white hover:bg-slate-700 transition-colors"
            title="Back to file upload"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs uppercase font-mono tracking-wider px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                {result.type === 'report' ? 'Behavioral Sandbox Telemetry' : 'Static PE Binary Inspection'}
              </span>
              <span className="text-xs text-slate-500 font-mono">
                ID: {result.data.binaryId?.slice(0, 8)}...
              </span>
            </div>
            <h2 className="text-lg font-bold text-slate-100 truncate max-w-md sm:max-w-xl">
              {result.data.filename}
            </h2>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={handleCopyJson}
            className="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-300 hover:text-white transition-all flex items-center gap-1.5 border border-slate-700/60"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            {copied ? 'Copied' : 'Copy JSON'}
          </button>
          <button
            type="button"
            onClick={handleExportJson}
            className="px-3.5 py-2 rounded-xl bg-cyan-500/10 hover:bg-cyan-500/20 text-xs font-medium text-cyan-400 border border-cyan-500/30 transition-all flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            Export Report
          </button>
        </div>
      </div>

      {result.type === 'report' ? (
        <ReportResultView data={result.data} activeTab={activeTab} setActiveTab={setActiveTab} />
      ) : (
        <BinaryResultView data={result.data} />
      )}
    </div>
  );
};

/* -------------------------------------------------------------------------- */
/* BEHAVIORAL / SANDBOX REPORT VIEW                                           */
/* -------------------------------------------------------------------------- */

interface ReportResultViewProps {
  data: ReportAnalysisResult;
  activeTab: string;
  setActiveTab: (tab: string) => void;
}

const ReportResultView: React.FC<ReportResultViewProps> = ({ data, activeTab, setActiveTab }) => {
  const trustScore = Math.round(data.trustScore || 0);

  const getTrustColor = (score: number) => {
    if (score >= 70) return { bg: 'bg-emerald-500/10', border: 'border-emerald-500/30', text: 'text-emerald-400', glow: 'glow-emerald' };
    if (score >= 40) return { bg: 'bg-amber-500/10', border: 'border-amber-500/30', text: 'text-amber-400', glow: 'glow-amber' };
    return { bg: 'bg-rose-500/10', border: 'border-rose-500/30', text: 'text-rose-400', glow: 'glow-rose' };
  };

  const trustTheme = getTrustColor(trustScore);

  const riskBadgeColors: Record<string, string> = {
    critical: 'bg-rose-950/80 border-rose-600 text-rose-300 glow-rose',
    high: 'bg-rose-900/60 border-rose-500 text-rose-300',
    medium: 'bg-amber-900/60 border-amber-500 text-amber-300',
    low: 'bg-emerald-900/60 border-emerald-500 text-emerald-300',
  };

  const riskKey = (data.riskLevel || 'low').toLowerCase();
  const riskClass = riskBadgeColors[riskKey] || riskBadgeColors.medium;

  const analysis = data.analysis || {};
  const behaviors = analysis.behaviors || [];
  const apicalls = analysis.apicalls || [];
  const network = analysis.network || [];
  const dropped = analysis.dropped || [];
  const mutexes = analysis.mutexes || [];

  return (
    <div className="space-y-6">
      {/* Hero Scoreboard Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Trust Score Card */}
        <div className={`p-6 rounded-2xl ${trustTheme.bg} border ${trustTheme.border} ${trustTheme.glow} backdrop-blur-xl relative overflow-hidden`}>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs uppercase font-mono tracking-wider text-slate-400">Trust Score</span>
            <ShieldCheck className={`w-5 h-5 ${trustTheme.text}`} />
          </div>
          <div className="flex items-baseline gap-2">
            <span className={`text-5xl font-black font-mono ${trustTheme.text}`}>
              {trustScore}
            </span>
            <span className="text-xs font-mono text-slate-500">/ 100</span>
          </div>
          <p className="text-xs text-slate-400 mt-2">
            {trustScore >= 70 ? 'High confidence benign behavior' : trustScore >= 40 ? 'Moderate suspicious activity detected' : 'Severe malicious indicators identified'}
          </p>
        </div>

        {/* Risk Level Card */}
        <div className="p-6 rounded-2xl bg-slate-900/70 border border-slate-800 backdrop-blur-xl">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs uppercase font-mono tracking-wider text-slate-400">Risk Assessment</span>
            <ShieldAlert className="w-5 h-5 text-slate-400" />
          </div>
          <div className="mt-1">
            <span className={`inline-flex items-center px-3.5 py-1.5 rounded-lg text-sm font-bold uppercase tracking-wider border ${riskClass}`}>
              {data.riskLevel || 'Unknown'} Risk
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-3">
            Triggered <span className="text-slate-200 font-semibold">{data.alerts?.length || 0}</span> behavioral alerts
          </p>
        </div>

        {/* ML Risk Score */}
        <div className="p-6 rounded-2xl bg-slate-900/70 border border-slate-800 backdrop-blur-xl">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs uppercase font-mono tracking-wider text-slate-400">ML Heuristic Classifier</span>
            <Activity className="w-5 h-5 text-cyan-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-black font-mono text-cyan-400">
              {data.mlScore ? (data.mlScore.riskScore * 100).toFixed(1) : 'N/A'}%
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-2 capitalize">
            Verdict: <span className="text-slate-200 font-semibold">{data.mlScore?.classification || 'Standard'}</span>
          </p>
        </div>

        {/* File Metadata */}
        <div className="p-6 rounded-2xl bg-slate-900/70 border border-slate-800 backdrop-blur-xl">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs uppercase font-mono tracking-wider text-slate-400">Entropy & Size</span>
            <Boxes className="w-5 h-5 text-purple-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-black font-mono text-purple-400">
              {typeof data.entropy === 'number' ? data.entropy.toFixed(3) : '0.000'}
            </span>
            <span className="text-xs font-mono text-slate-500">/ 8.0</span>
          </div>
          <p className="text-xs text-slate-400 mt-2">
            Size: <span className="text-slate-200 font-semibold">{(data.fileSize / 1024).toFixed(1)} KB</span>
          </p>
        </div>
      </div>

      {/* SHA256 Fingerprint Banner */}
      {data.sha256 && (
        <div className="p-4 rounded-xl bg-slate-900/40 border border-slate-800/80 flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2 overflow-hidden">
            <span className="text-xs uppercase font-mono text-slate-400 font-semibold">SHA-256:</span>
            <code className="text-xs text-cyan-400 font-mono truncate">{data.sha256}</code>
          </div>
        </div>
      )}

      {/* Navigation tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
        <button
          type="button"
          onClick={() => setActiveTab('overview')}
          className={`px-4 py-2 rounded-lg text-xs font-semibold uppercase tracking-wider transition-all flex items-center gap-2 ${
            activeTab === 'overview'
              ? 'bg-slate-800 text-cyan-400 border border-slate-700'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <AlertTriangle className="w-3.5 h-3.5" />
          Alerts ({data.alerts?.length || 0})
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('behavior')}
          className={`px-4 py-2 rounded-lg text-xs font-semibold uppercase tracking-wider transition-all flex items-center gap-2 ${
            activeTab === 'behavior'
              ? 'bg-slate-800 text-cyan-400 border border-slate-700'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Activity className="w-3.5 h-3.5" />
          Behaviors & APIs ({behaviors.length + apicalls.length})
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('network')}
          className={`px-4 py-2 rounded-lg text-xs font-semibold uppercase tracking-wider transition-all flex items-center gap-2 ${
            activeTab === 'network'
              ? 'bg-slate-800 text-cyan-400 border border-slate-700'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Network className="w-3.5 h-3.5" />
          Network C2 ({network.length})
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('json')}
          className={`px-4 py-2 rounded-lg text-xs font-semibold uppercase tracking-wider transition-all flex items-center gap-2 ${
            activeTab === 'json'
              ? 'bg-slate-800 text-cyan-400 border border-slate-700'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          <Terminal className="w-3.5 h-3.5" />
          Raw Telemetry
        </button>
      </div>

      {/* Tab 1: Alerts Overview */}
      {activeTab === 'overview' && (
        <div className="space-y-3">
          {(!data.alerts || data.alerts.length === 0) ? (
            <div className="p-8 text-center bg-slate-900/40 rounded-2xl border border-slate-800 text-slate-400">
              <Check className="w-8 h-8 mx-auto text-emerald-400 mb-2" />
              <p className="text-sm font-semibold text-slate-200">No Threat Alerts Triggered</p>
              <p className="text-xs text-slate-500 mt-1">This report shows no high-confidence malicious flags.</p>
            </div>
          ) : (
            data.alerts.map((alert, idx) => {
              const sev = (alert.severity || 'low').toLowerCase();
              const badgeColors: Record<string, string> = {
                critical: 'bg-rose-500/20 text-rose-400 border-rose-500/40',
                high: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
                medium: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
                low: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
              };
              const badge = badgeColors[sev] || badgeColors.low;

              return (
                <div
                  key={idx}
                  className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 flex items-center justify-between gap-4 transition-all hover:border-slate-700"
                >
                  <div className="flex items-center gap-3">
                    <AlertTriangle className={`w-5 h-5 flex-shrink-0 ${sev === 'high' || sev === 'critical' ? 'text-rose-400' : 'text-amber-400'}`} />
                    <span className="text-sm font-medium text-slate-200">{alert.message}</span>
                  </div>
                  <span className={`px-2.5 py-1 rounded text-xs font-mono font-bold uppercase border ${badge}`}>
                    {alert.severity}
                  </span>
                </div>
              );
            })
          )}
        </div>
      )}

      {/* Tab 2: Behaviors & Suspicious APIs */}
      {activeTab === 'behavior' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Behaviors */}
          <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3">
            <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              Observed System Behaviors ({behaviors.length})
            </h4>
            <div className="space-y-2">
              {behaviors.length === 0 ? (
                <p className="text-xs text-slate-500">None detected.</p>
              ) : (
                behaviors.map((b: string, i: number) => (
                  <div key={i} className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 text-xs text-slate-300 flex items-start gap-2">
                    <span className="text-cyan-400 font-mono">›</span>
                    <span>{b}</span>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Suspicious APIs */}
          <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3">
            <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <Terminal className="w-4 h-4 text-rose-400" />
              Critical API Call Sequences ({apicalls.length})
            </h4>
            <div className="flex flex-wrap gap-2">
              {apicalls.length === 0 ? (
                <p className="text-xs text-slate-500">None recorded.</p>
              ) : (
                apicalls.map((api: string, i: number) => (
                  <span key={i} className="px-2.5 py-1 rounded bg-rose-950/40 border border-rose-800/40 font-mono text-xs text-rose-300">
                    {api}
                  </span>
                ))
              )}
            </div>

            {/* Mutexes */}
            {mutexes.length > 0 && (
              <div className="pt-4 border-t border-slate-800 space-y-2">
                <h5 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-2">
                  <Lock className="w-3.5 h-3.5 text-purple-400" />
                  Locked Mutexes ({mutexes.length})
                </h5>
                <div className="flex flex-wrap gap-2">
                  {mutexes.map((m: string, i: number) => (
                    <span key={i} className="px-2.5 py-1 rounded bg-purple-950/40 border border-purple-800/40 font-mono text-xs text-purple-300">
                      {m}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 3: Network C2 Connections */}
      {activeTab === 'network' && (
        <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
          <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-2">
            <Network className="w-4 h-4 text-cyan-400" />
            Command & Control (C2) Network Traffic ({network.length})
          </h4>
          {network.length === 0 ? (
            <p className="text-xs text-slate-500">No external network connections observed in sandbox execution.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-500">
                    <th className="py-2.5 px-3">Destination Host</th>
                    <th className="py-2.5 px-3">Port</th>
                    <th className="py-2.5 px-3">Protocol</th>
                    <th className="py-2.5 px-3">URI / Payload</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {network.map((conn: any, i: number) => (
                    <tr key={i} className="hover:bg-slate-800/30">
                      <td className="py-2.5 px-3 text-cyan-400 font-semibold">{conn.dst}</td>
                      <td className="py-2.5 px-3 text-slate-400">{conn.dport}</td>
                      <td className="py-2.5 px-3 uppercase text-purple-400">{conn.protocol}</td>
                      <td className="py-2.5 px-3 text-slate-400">{conn.uri || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Dropped files if any */}
          {dropped.length > 0 && (
            <div className="pt-4 border-t border-slate-800 space-y-2">
              <h5 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-2">
                <FileCode2 className="w-3.5 h-3.5 text-amber-400" />
                Dropped Files / Payloads ({dropped.length})
              </h5>
              <div className="space-y-1.5">
                {dropped.map((df: any, i: number) => (
                  <div key={i} className="p-2.5 rounded bg-slate-950/50 border border-slate-800 flex items-center justify-between text-xs font-mono">
                    <span className="text-amber-300">{df.name}</span>
                    <span className="text-slate-500">{(df.size / 1024).toFixed(1)} KB ({df.type})</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 4: Raw JSON */}
      {activeTab === 'json' && (
        <div className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400">
            <span>Raw Analysis Telemetry Payload</span>
          </div>
          <pre className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-300 overflow-x-auto max-h-[500px]">
            {JSON.stringify(data, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
};

/* -------------------------------------------------------------------------- */
/* STATIC PE BINARY RESULT VIEW                                               */
/* -------------------------------------------------------------------------- */

interface BinaryResultViewProps {
  data: BinaryAnalysisResult;
}

const BinaryResultView: React.FC<BinaryResultViewProps> = ({ data }) => {
  const isMalicious = data.classification?.toLowerCase() === 'malicious' || data.yaraMatched || (data.mlRiskScore > 0.7);
  const isSuspicious = data.classification?.toLowerCase() === 'suspicious' || (data.mlRiskScore > 0.4);

  const matchedRulesList: string[] = Array.isArray(data.matchedRules)
    ? data.matchedRules
    : typeof data.matchedRules === 'string' && data.matchedRules.trim()
    ? data.matchedRules.split(/[\r\n,]+/).map(s => s.trim()).filter(Boolean)
    : [];

  return (
    <div className="space-y-6">
      {/* Hero Scoreboard Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Classification Card */}
        <div className={`p-6 rounded-2xl border backdrop-blur-xl ${
          isMalicious
            ? 'bg-rose-500/10 border-rose-500/30 glow-rose text-rose-400'
            : isSuspicious
            ? 'bg-amber-500/10 border-amber-500/30 glow-amber text-amber-400'
            : 'bg-emerald-500/10 border-emerald-500/30 glow-emerald text-emerald-400'
        }`}>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs uppercase font-mono tracking-wider text-slate-400">Classification</span>
            {isMalicious ? <ShieldAlert className="w-5 h-5 text-rose-400" /> : <ShieldCheck className="w-5 h-5 text-emerald-400" />}
          </div>
          <div className="text-3xl font-black font-mono uppercase tracking-wider">
            {data.classification || (isMalicious ? 'MALICIOUS' : 'CLEAN')}
          </div>
          <p className="text-xs text-slate-400 mt-2">
            {data.packed ? '⚠️ Packed / Obfuscated binary' : 'Standard unpacked Portable Executable'}
          </p>
        </div>

        {/* YARA Match Card */}
        <div className="p-6 rounded-2xl bg-slate-900/70 border border-slate-800 backdrop-blur-xl">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs uppercase font-mono tracking-wider text-slate-400">YARA Signatures</span>
            <Terminal className="w-5 h-5 text-slate-400" />
          </div>
          <div className="text-2xl font-black font-mono">
            {data.yaraMatched ? (
              <span className="text-rose-400 font-bold">{matchedRulesList.length} Matched</span>
            ) : (
              <span className="text-emerald-400 font-bold">0 Matches</span>
            )}
          </div>
          <p className="text-xs text-slate-400 mt-2">
            {data.yaraMatched ? 'Known malware rule triggered' : 'No pattern matches in rule database'}
          </p>
        </div>

        {/* ML Risk Score */}
        <div className="p-6 rounded-2xl bg-slate-900/70 border border-slate-800 backdrop-blur-xl">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs uppercase font-mono tracking-wider text-slate-400">ML Risk Factor</span>
            <Activity className="w-5 h-5 text-cyan-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-black font-mono text-cyan-400">
              {(data.mlRiskScore * 100).toFixed(1)}%
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-2">
            {data.mlRiskScore > 0.7 ? 'High anomaly detected' : data.mlRiskScore > 0.4 ? 'Moderate risk variance' : 'Low structural risk'}
          </p>
        </div>

        {/* Machine Spec */}
        <div className="p-6 rounded-2xl bg-slate-900/70 border border-slate-800 backdrop-blur-xl">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs uppercase font-mono tracking-wider text-slate-400">Architecture</span>
            <Cpu className="w-5 h-5 text-purple-400" />
          </div>
          <div className="text-2xl font-black font-mono text-purple-400">
            {data.machineType || 'I386'}
          </div>
          <p className="text-xs text-slate-400 mt-2">
            Subsystem: <span className="text-slate-200 font-semibold">{data.subsystem || 'Windows GUI'}</span>
          </p>
        </div>
      </div>

      {/* YARA Rules Match Box if matched */}
      {data.yaraMatched && matchedRulesList.length > 0 && (
        <div className="p-5 rounded-2xl bg-rose-950/30 border border-rose-800/60 space-y-2">
          <h4 className="text-xs font-mono uppercase tracking-wider text-rose-400 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            Detected YARA Rules
          </h4>
          <div className="flex flex-wrap gap-2">
            {matchedRulesList.map((rule, idx) => (
              <span key={idx} className="px-3 py-1.5 rounded-lg bg-rose-500/20 border border-rose-500/40 text-rose-300 font-mono text-xs font-semibold">
                {rule}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Technical PE Header Info */}
      <div className="p-6 rounded-2xl bg-slate-900/70 border border-slate-800 space-y-4">
        <h3 className="text-sm font-mono uppercase tracking-wider text-slate-300 flex items-center gap-2">
          <Cpu className="w-4 h-4 text-cyan-400" />
          Portable Executable (PE) Headers
        </h3>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800">
            <p className="text-xs text-slate-500 font-mono">Entry Point</p>
            <p className="text-sm font-mono text-slate-200 font-semibold mt-1">
              0x{data.entryPoint ? data.entryPoint.toString(16).toUpperCase() : '00000000'}
            </p>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800">
            <p className="text-xs text-slate-500 font-mono">Image Base</p>
            <p className="text-sm font-mono text-slate-200 font-semibold mt-1">
              0x{data.imageBase ? data.imageBase.toString(16).toUpperCase() : '00400000'}
            </p>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800">
            <p className="text-xs text-slate-500 font-mono">Machine Type</p>
            <p className="text-sm font-mono text-slate-200 font-semibold mt-1">
              {data.machineType || 'I386'}
            </p>
          </div>

          <div className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800">
            <p className="text-xs text-slate-500 font-mono">Sections Count</p>
            <p className="text-sm font-mono text-slate-200 font-semibold mt-1">
              {data.sections?.length || 0}
            </p>
          </div>
        </div>
      </div>

      {/* PE Sections Table */}
      {data.sections && data.sections.length > 0 && (
        <div className="p-6 rounded-2xl bg-slate-900/70 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-mono uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <Layers className="w-4 h-4 text-purple-400" />
              PE Section Table & Entropy Distribution
            </h3>
            <span className="text-xs text-slate-500 font-mono">Entropy &gt; 7.0 indicates packing</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-500">
                  <th className="py-2.5 px-3">Name</th>
                  <th className="py-2.5 px-3">RVA</th>
                  <th className="py-2.5 px-3">Virtual Size</th>
                  <th className="py-2.5 px-3">Raw Size</th>
                  <th className="py-2.5 px-3">Entropy</th>
                  <th className="py-2.5 px-3">Characteristics</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {data.sections.map((sec, idx) => {
                  const ent = sec.entropy || 0;
                  const entColor = ent > 7.0 ? 'text-rose-400 bg-rose-950/60' : ent > 6.0 ? 'text-amber-400 bg-amber-950/60' : 'text-emerald-400 bg-emerald-950/60';

                  return (
                    <tr key={idx} className="hover:bg-slate-800/30">
                      <td className="py-3 px-3 font-bold text-cyan-400">{sec.name}</td>
                      <td className="py-3 px-3 text-slate-400">0x{sec.rva ? sec.rva.toString(16).toUpperCase() : '0'}</td>
                      <td className="py-3 px-3 text-slate-300">{sec.virtualSize?.toLocaleString()} B</td>
                      <td className="py-3 px-3 text-slate-300">{sec.rawSize?.toLocaleString()} B</td>
                      <td className="py-3 px-3">
                        <span className={`px-2 py-0.5 rounded font-bold ${entColor}`}>
                          {ent.toFixed(3)}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-slate-400 max-w-xs truncate" title={sec.characteristics}>
                        {sec.characteristics || '-'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
