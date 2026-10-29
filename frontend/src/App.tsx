import { useState, useEffect } from 'react';
import {
  Shield,
  Activity,
  Cpu,
  Layers,
  Network,
  RefreshCw,
  Terminal,
  Zap,
  AlertCircle
} from 'lucide-react';
import { FileUpload } from './components/FileUpload';
import { AnalysisResults } from './components/AnalysisResults';
import { checkHealth } from './services/api';
import type { UnifiedAnalysis } from './types/analysis';

function App() {
  const [analysisResult, setAnalysisResult] = useState<UnifiedAnalysis | null>(null);
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);
  const [backendDetails, setBackendDetails] = useState<string>('');
  const [checkingHealth, setCheckingHealth] = useState<boolean>(false);

  const runHealthCheck = async () => {
    setCheckingHealth(true);
    try {
      const data = await checkHealth();
      if (data && (data.status === 'UP' || data.status === 'OK' || data.service)) {
        setBackendOnline(true);
        setBackendDetails(data.service || 'Threat Detection Backend');
      } else {
        setBackendOnline(true);
        setBackendDetails('Threat Detection Backend');
      }
    } catch (err) {
      setBackendOnline(false);
      setBackendDetails('Unavailable');
    } finally {
      setCheckingHealth(false);
    }
  };

  useEffect(() => {
    runHealthCheck();
    const interval = setInterval(runHealthCheck, 15000);
    return () => clearInterval(interval);
  }, []);

  const handleReset = () => {
    setAnalysisResult(null);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-slate-950">
      {/* Background ambient grid & lighting */}
      <div className="fixed inset-0 pointer-events-none bg-[radial-gradient(ellipse_80%_80%_at_50%_-20%,rgba(14,165,233,0.15),rgba(255,255,255,0))] -z-10" />
      <div className="fixed inset-0 pointer-events-none bg-[linear-gradient(to_right,#1e293b0a_1px,transparent_1px),linear-gradient(to_bottom,#1e293b0a_1px,transparent_1px)] bg-[size:4rem_4rem] -z-10" />

      {/* Header / Top Navigation */}
      <header className="sticky top-0 z-50 backdrop-blur-md bg-slate-950/80 border-b border-slate-800/80 shadow-lg">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-20">
            {/* Brand Title */}
            <div className="flex items-center gap-4">
              <div className="relative">
                <div className="w-12 h-12 rounded-xl bg-gradient-to-tr from-cyan-600 via-sky-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 ring-1 ring-cyan-400/30">
                  <Shield className="w-6 h-6 text-white" />
                </div>
                <div className="absolute -bottom-1 -right-1 w-4 h-4 rounded-full bg-slate-950 flex items-center justify-center">
                  <span className={`w-2.5 h-2.5 rounded-full ${backendOnline ? 'bg-emerald-400 shadow-sm shadow-emerald-400' : 'bg-rose-500 animate-ping'}`} />
                </div>
              </div>

              <div>
                <div className="flex items-center gap-2">
                  <h1 className="text-xl font-bold tracking-tight bg-gradient-to-r from-white via-slate-100 to-slate-400 bg-clip-text text-transparent">
                    THREAT-RADAR
                  </h1>
                  <span className="px-2 py-0.5 text-[10px] font-mono uppercase tracking-widest font-semibold rounded bg-cyan-950/80 text-cyan-400 border border-cyan-800/50">
                    SOC v2.5
                  </span>
                </div>
                <p className="text-xs text-slate-400 font-mono">
                  Advanced PE Binary Forensics & Dynamic Telemetry Engine
                </p>
              </div>
            </div>

            {/* Engine Status & Capabilities */}
            <div className="flex items-center gap-3">
              {/* Feature Tags (Desktop) */}
              <div className="hidden lg:flex items-center gap-2 text-xs font-mono text-slate-400">
                <span className="px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 flex items-center gap-1.5">
                  <Cpu className="w-3.5 h-3.5 text-cyan-400" /> PortEx PE
                </span>
                <span className="px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 flex items-center gap-1.5">
                  <Zap className="w-3.5 h-3.5 text-amber-400" /> YARA 4.5.5
                </span>
                <span className="px-2.5 py-1 rounded-md bg-slate-900 border border-slate-800 flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5 text-indigo-400" /> AI Risk Scorer
                </span>
              </div>

              <div className="h-6 w-px bg-slate-800 hidden sm:block" />

              {/* Live Health Badge */}
              <div className="flex items-center gap-2">
                <div
                  className={`px-3 py-1.5 rounded-lg border text-xs font-mono flex items-center gap-2 transition-all duration-300 ${
                    backendOnline === true
                      ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-400'
                      : backendOnline === false
                      ? 'bg-rose-950/40 border-rose-500/40 text-rose-400'
                      : 'bg-amber-950/40 border-amber-500/40 text-amber-400'
                  }`}
                  title={backendDetails}
                >
                  <span className="relative flex h-2 w-2">
                    <span
                      className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                        backendOnline === true
                          ? 'bg-emerald-400'
                          : backendOnline === false
                          ? 'bg-rose-400'
                          : 'bg-amber-400'
                      }`}
                    />
                    <span
                      className={`relative inline-flex rounded-full h-2 w-2 ${
                        backendOnline === true
                          ? 'bg-emerald-500'
                          : backendOnline === false
                          ? 'bg-rose-500'
                          : 'bg-amber-500'
                      }`}
                    />
                  </span>
                  <span className="font-semibold">
                    {backendOnline === true
                      ? 'BACKEND ONLINE'
                      : backendOnline === false
                      ? 'BACKEND OFFLINE'
                      : 'CONNECTING...'}
                  </span>
                </div>

                <button
                  onClick={runHealthCheck}
                  disabled={checkingHealth}
                  title="Check Backend Connection"
                  className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-slate-200 transition-colors disabled:opacity-50"
                >
                  <RefreshCw className={`w-4 h-4 ${checkingHealth ? 'animate-spin text-cyan-400' : ''}`} />
                </button>
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Main Body */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {!analysisResult ? (
          <div className="space-y-10">
            {/* Hero Section */}
            <div className="relative rounded-2xl overflow-hidden border border-slate-800/80 bg-gradient-to-b from-slate-900/90 to-slate-950 p-8 sm:p-10 shadow-2xl">
              <div className="absolute top-0 right-0 -mr-16 -mt-16 w-64 h-64 rounded-full bg-cyan-500/10 blur-3xl pointer-events-none" />
              <div className="absolute bottom-0 left-0 -ml-16 -mb-16 w-64 h-64 rounded-full bg-indigo-500/10 blur-3xl pointer-events-none" />

              <div className="max-w-3xl space-y-4 relative z-10">
                <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-mono font-medium">
                  <Terminal className="w-3.5 h-3.5" />
                  Dual-Engine Pipeline Active
                </div>
                <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">
                  High-Assurance Threat Analysis & Risk Quantification
                </h2>
                <p className="text-slate-300 text-base sm:text-lg leading-relaxed">
                  Analyze executable PE binaries (<span className="text-cyan-400 font-mono">.exe</span>,{' '}
                  <span className="text-cyan-400 font-mono">.dll</span>, <span className="text-cyan-400 font-mono">.sys</span>)
                  with in-depth static parsing & YARA pattern scanning, or ingest behavioral sandbox telemetry reports (
                  <span className="text-cyan-400 font-mono">.json</span>) for automated MITRE ATT&CK risk scoring.
                </p>
              </div>

              {/* Feature Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-8 pt-8 border-t border-slate-800">
                <div className="flex items-start gap-3">
                  <div className="p-2 rounded-lg bg-cyan-950/60 border border-cyan-800/40 text-cyan-400 mt-1">
                    <Cpu className="w-4 h-4" />
                  </div>
                  <div>
                    <h4 className="text-sm font-semibold text-slate-200">PE Structural Forensics</h4>
                    <p className="text-xs text-slate-400 mt-0.5">Section entropy mapping, entry points, machine types & packer detection.</p>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <div className="p-2 rounded-lg bg-amber-950/60 border border-amber-800/40 text-amber-400 mt-1">
                    <Zap className="w-4 h-4" />
                  </div>
                  <div>
                    <h4 className="text-sm font-semibold text-slate-200">YARA 4.5.5 Scanning</h4>
                    <p className="text-xs text-slate-400 mt-0.5">Automated rule signatures for suspicious strings, webshells & known malware.</p>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <div className="p-2 rounded-lg bg-indigo-950/60 border border-indigo-800/40 text-indigo-400 mt-1">
                    <Layers className="w-4 h-4" />
                  </div>
                  <div>
                    <h4 className="text-sm font-semibold text-slate-200">AI Risk Scoring</h4>
                    <p className="text-xs text-slate-400 mt-0.5">Calibrated risk modeling combining static features with heuristic classifiers.</p>
                  </div>
                </div>

                <div className="flex items-start gap-3">
                  <div className="p-2 rounded-lg bg-emerald-950/60 border border-emerald-800/40 text-emerald-400 mt-1">
                    <Network className="w-4 h-4" />
                  </div>
                  <div>
                    <h4 className="text-sm font-semibold text-slate-200">C2 & Sandbox Ingestion</h4>
                    <p className="text-xs text-slate-400 mt-0.5">Correlates network sockets, API call patterns, and dropped artifact alerts.</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Offline Alert if backend unreachable */}
            {backendOnline === false && (
              <div className="rounded-xl border border-rose-500/30 bg-rose-950/20 p-4 flex items-center justify-between text-rose-300">
                <div className="flex items-center gap-3">
                  <AlertCircle className="w-5 h-5 text-rose-400 shrink-0" />
                  <div className="text-sm">
                    <span className="font-semibold text-rose-200">Backend service not responding on http://localhost:8080.</span>
                    <p className="text-xs text-rose-400/90 mt-0.5">
                      Ensure the Spring Boot server is running via <code className="bg-slate-900 px-1.5 py-0.5 rounded text-rose-200">.\mvnw.cmd spring-boot:run</code>.
                    </p>
                  </div>
                </div>
                <button
                  onClick={runHealthCheck}
                  className="px-3 py-1.5 rounded-lg bg-rose-900/40 hover:bg-rose-900/60 border border-rose-700/50 text-xs font-mono font-semibold transition-colors"
                >
                  Retry Connection
                </button>
              </div>
            )}

            {/* File Upload Component */}
            <FileUpload
              onAnalysisComplete={setAnalysisResult}
              backendOnline={backendOnline ?? true}
            />
          </div>
        ) : (
          <AnalysisResults result={analysisResult} onReset={handleReset} />
        )}
      </main>

      {/* Footer */}
      <footer className="mt-auto border-t border-slate-900 bg-slate-950/90 py-6">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-slate-500 font-mono">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-500 inline-block" />
            <span>Threat Detection Platform &copy; 2026 TheSecureSyndicate</span>
          </div>

          <div className="flex wrap items-center gap-4">
            <span className="hover:text-slate-400 transition-colors">Vite + React 19 + Tailwind</span>
            <span className="text-slate-800">&bull;</span>
            <span className="hover:text-slate-400 transition-colors">Spring Boot 3.3.4</span>
            <span className="text-slate-800">&bull;</span>
            <span className="hover:text-slate-400 transition-colors">PortEx 5.0.7</span>
            <span className="text-slate-800">&bull;</span>
            <span className="hover:text-slate-400 transition-colors">YARA 4.5.5</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
