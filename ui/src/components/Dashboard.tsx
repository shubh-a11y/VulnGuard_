import { useEffect, useState, useRef } from 'react';
import { motion } from 'framer-motion';
import { Shield, Upload, Activity, Code, TerminalSquare, AlertCircle, Play, Square, BarChart3, RefreshCw } from 'lucide-react';
import { cn } from '../lib/utils';
import AgentFeed from './AgentFeed';
import { MetricCard, ModelHealthCard } from './dashboard/MetricCards';

const API = 'http://localhost:8000';

interface Metrics {
  total_scans: number;
  vulnerabilities_found: number;
  patches_validated: number;
  patch_rate?: number;
}

interface ModelHealth {
  recall: number;
  precision: number;
  patch_success_rate: number;
}

interface EvaluationHealth {
  evaluation_json_exists: boolean;
  evaluation_summary_exists: boolean;
  figures: string[];
  figures_dir: string;
}

interface SuccessfulFix {
  scan_id: string;
  function_id: string;
  file_path: string;
  judge_verdict: string;
  vulnerability_type: string | null;
  severity: string | null;
  risk_score: number | null;
  updated_at: string;
}

export default function Dashboard() {
  const [file, setFile] = useState<File | null>(null);
  const [functions, setFunctions] = useState<any[]>([]);
  const [selectedFunc, setSelectedFunc] = useState<any | null>(null);
  const [events, setEvents] = useState<any[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [uploadError, setUploadError] = useState('');
  const [metrics, setMetrics] = useState<Metrics>({ total_scans: 0, vulnerabilities_found: 0, patches_validated: 0 });
  const [history, setHistory] = useState<any[]>([]);
  const [batchProgress, setBatchProgress] = useState({ current: 0, total: 0 });
  const [verdicts, setVerdicts] = useState<Record<string, number>>({});
  const [modelHealth, setModelHealth] = useState<ModelHealth>({ recall: 0, precision: 0, patch_success_rate: 0 });
  const [evaluation, setEvaluation] = useState<EvaluationHealth | null>(null);
  const [fixes, setFixes] = useState<SuccessfulFix[]>([]);
  const [dataError, setDataError] = useState('');
  const [runningEvaluation, setRunningEvaluation] = useState(false);
  const [evaluationError, setEvaluationError] = useState('');
  const wsRef = useRef<WebSocket | null>(null);
  const cancelledRef = useRef(false);

  const loadDashboardData = async () => {
    setDataError('');
    const requests = [
      fetch(`${API}/api/metrics`),
      fetch(`${API}/api/scan/status`),
      fetch(`${API}/api/scan/verdict-distribution`),
      fetch(`${API}/api/scan/successful-fixes?limit=6`),
      fetch(`${API}/api/evaluation/model-health`),
      fetch(`${API}/api/evaluation/health`),
    ];
    const [metricsRes, scansRes, verdictRes, fixesRes, healthRes, evaluationRes] = await Promise.allSettled(requests);
    try {
      if (metricsRes.status === 'fulfilled' && metricsRes.value.ok) setMetrics(await metricsRes.value.json());
      if (scansRes.status === 'fulfilled' && scansRes.value.ok) {
        const data = await scansRes.value.json();
        setHistory(Object.values(data.scans).slice(0, 5));
      }
      if (verdictRes.status === 'fulfilled' && verdictRes.value.ok) setVerdicts(await verdictRes.value.json());
      if (fixesRes.status === 'fulfilled' && fixesRes.value.ok) {
        setFixes(await fixesRes.value.json());
      } else {
        // Surface the failure instead of letting an empty table look like
        // "no validated fixes exist".
        setDataError('Could not load validated fixes from the backend.');
      }
      if (healthRes.status === 'fulfilled' && healthRes.value.ok) setModelHealth(await healthRes.value.json());
      if (evaluationRes.status === 'fulfilled' && evaluationRes.value.ok) setEvaluation(await evaluationRes.value.json());
    } catch {
      // The scan workflow reports connection errors where the user acts on them.
    }
  };

  useEffect(() => {
    loadDashboardData();
  }, []);

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files?.[0]) return;
    const uploadedFile = e.target.files[0];
    setFile(uploadedFile);
    setFunctions([]);
    setSelectedFunc(null);
    setUploadError('');

    const formData = new FormData();
    formData.append('file', uploadedFile);

    try {
      const res = await fetch(`${API}/upload`, {
        method: 'POST',
        body: formData,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Upload failed');
      setFunctions(data.functions);
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : 'Upload failed');
    }
  };

  const runScan = (func: any, clearEvents: boolean) => new Promise<void>((resolve) => {
    setSelectedFunc(func);
    if (clearEvents) setEvents([]);
    setEvents((previous) => [
      ...previous,
      { type: 'batch_function', function_name: func.name, relative_path: func.relative_path },
    ]);

    if (wsRef.current) wsRef.current.close();
    const ws = new WebSocket('ws://localhost:8000/ws/scan');
    wsRef.current = ws;
    let finished = false;
    const finish = () => {
      if (finished) return;
      finished = true;
      resolve();
    };

    ws.onopen = () => {
      ws.send(JSON.stringify(func));
    };

    ws.onmessage = (event) => {
      let data: any;
      try {
        data = JSON.parse(event.data);
      } catch {
        data = {
          type: 'error',
          stage: 'stream',
          message: 'Received a malformed event from the backend.',
        };
      }
      setEvents((prev) => [...prev, { ...data, function_name: func.name }]);
      if (data.type === 'complete' || data.type === 'error') {
        ws.close();
        finish();
      }
    };

    ws.onerror = () => {
      setEvents((prev) => [...prev, { type: 'error', message: 'WebSocket connection failed', function_name: func.name }]);
      finish();
    };
    ws.onclose = finish;
  });

  const startScan = async (func: any) => {
    cancelledRef.current = false;
    setIsScanning(true);
    setBatchProgress({ current: 1, total: 1 });
    await runScan(func, true);
    setIsScanning(false);
    setBatchProgress({ current: 0, total: 0 });
    loadDashboardData();
  };

  const startBatchScan = async () => {
    cancelledRef.current = false;
    setIsScanning(true);
    setEvents([]);
    for (let index = 0; index < functions.length; index += 1) {
      if (cancelledRef.current) break;
      setBatchProgress({ current: index + 1, total: functions.length });
      await runScan(functions[index], false);
    }
    setIsScanning(false);
    setBatchProgress({ current: 0, total: 0 });
    loadDashboardData();
  };

  const cancelScan = () => {
    cancelledRef.current = true;
    wsRef.current?.close();
    setIsScanning(false);
    setBatchProgress({ current: 0, total: 0 });
  };

  const runEvaluation = async () => {
    setRunningEvaluation(true);
    setEvaluationError('');
    try {
      const res = await fetch(`${API}/api/evaluation/run`, { method: 'POST' });
      if (!res.ok) {
        const detail = await res.json().catch(() => ({}));
        throw new Error(detail.detail || 'Evaluation run failed');
      }
      await loadDashboardData();
    } catch (err) {
      setEvaluationError(err instanceof Error ? err.message : 'Evaluation run failed');
    } finally {
      setRunningEvaluation(false);
    }
  };

  const verdictEntries = Object.entries(verdicts);
  const figures = evaluation?.figures ?? [];

  return (
    <div className="min-h-screen p-8 lg:p-12 font-sans relative overflow-hidden">
      {/* Background Noise & Gradients */}
      <div className="fixed inset-0 z-0 pointer-events-none opacity-[0.03] bg-[url('https://grainy-gradients.vercel.app/noise.svg')]"></div>
      <div className="fixed top-[-20%] left-[-10%] w-[50%] h-[50%] rounded-full bg-blue-900/20 blur-[120px] pointer-events-none z-0"></div>
      
      <div className="relative z-10 max-w-7xl mx-auto">
        <header className="mb-8 flex flex-col gap-6 md:flex-row md:items-center md:justify-between">
          <motion.div 
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex items-center gap-4"
          >
            <div className="p-3 bg-white/5 rounded-2xl border border-white/10 shadow-2xl backdrop-blur-md">
              <Shield className="w-8 h-8 text-white" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight text-white">VulnGuard</h1>
              <p className="text-white/50 text-sm tracking-widest uppercase">Autonomous Security Agents</p>
            </div>
          </motion.div>
          <div className="grid w-full grid-cols-3 border-y border-white/10 md:w-auto md:min-w-[420px]">
            {[
              ['Scans', metrics.total_scans],
              ['Vulnerabilities', metrics.vulnerabilities_found],
              ['Validated', metrics.patches_validated],
            ].map(([label, value]) => (
              <div key={label} className="px-4 py-3 text-center">
                <div className="text-xl font-semibold text-white">{value}</div>
                <div className="text-xs text-white/40">{label}</div>
              </div>
            ))}
          </div>
        </header>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Upload & Code */}
          <div className="lg:col-span-4 flex flex-col gap-6">
            <motion.div 
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              className="glassmorphism rounded-3xl p-6"
            >
              <h2 className="text-lg font-medium text-white mb-4 flex items-center gap-2">
                <Upload className="w-5 h-5 text-white/50" /> Upload Target
              </h2>
              
              <label className="flex flex-col items-center justify-center w-full h-32 border-2 border-dashed border-white/20 rounded-2xl cursor-pointer hover:bg-white/5 hover:border-white/40 transition-all">
                <div className="flex flex-col items-center justify-center pt-5 pb-6">
                  <Upload className="w-8 h-8 mb-3 text-white/40" />
                  <p className="mb-2 text-sm text-white/60"><span className="font-semibold text-white">Upload source or ZIP</span></p>
                </div>
                <input type="file" accept=".py,.c,.h,.cpp,.cc,.cxx,.hpp,.java,.js,.mjs,.cjs,.zip" className="hidden" onChange={handleFileUpload} />
              </label>

              {uploadError && (
                <div className="mt-4 flex items-start gap-2 text-sm text-red-300">
                  <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>{uploadError}</span>
                </div>
              )}

              {file && (
                <div className="mt-6">
                  <div className="mb-3 flex items-center justify-between gap-3">
                    <h3 className="text-sm font-medium text-white/70">Detected Functions</h3>
                    {functions.length > 1 && !isScanning && (
                      <button
                        type="button"
                        onClick={startBatchScan}
                        className="flex items-center gap-1.5 text-xs text-white/60 hover:text-white"
                      >
                        <Play className="h-3.5 w-3.5" /> Scan all {functions.length}
                      </button>
                    )}
                  </div>
                  <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
                    {functions.map((f, i) => (
                      <button
                        key={i}
                        disabled={isScanning}
                        onClick={() => startScan(f)}
                        className={cn(
                          "w-full text-left p-3 rounded-lg border transition-all text-sm flex items-center justify-between group disabled:cursor-not-allowed disabled:opacity-50",
                          selectedFunc?.id === f.id 
                            ? "bg-white/10 border-white/30 text-white" 
                            : "bg-white/5 border-white/10 text-white/60 hover:bg-white/10 hover:text-white"
                        )}
                      >
                        <span className="min-w-0 flex items-center gap-2">
                          <Code className="w-4 h-4 shrink-0"/>
                          <span className="min-w-0">
                            <span className="block truncate">{f.name}</span>
                            <span className="block truncate text-xs text-white/35">{f.relative_path}</span>
                          </span>
                        </span>
                        <Activity className="w-4 h-4 opacity-0 group-hover:opacity-100 transition-opacity" />
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {history.length > 0 && (
                <div className="mt-6 border-t border-white/10 pt-4">
                  <h3 className="mb-3 text-xs font-medium text-white/40">Recent scans</h3>
                  <div className="space-y-2">
                    {history.map((scan) => (
                      <div key={scan.scan_id} className="flex items-center justify-between gap-3 text-xs">
                        <span className="truncate text-white/60">{scan.function_id}</span>
                        <span className="shrink-0 font-mono text-white/35">{scan.judge_verdict || scan.pipeline_status}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </motion.div>
          </div>

          {/* Right Column: Agent Feed */}
          <div className="lg:col-span-8 flex flex-col gap-6">
            <motion.div 
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="glassmorphism rounded-3xl p-0 overflow-hidden flex flex-col h-[700px]"
            >
              <div className="p-4 border-b border-white/10 bg-white/5 flex items-center gap-3">
                <TerminalSquare className="w-5 h-5 text-white/50" />
                <h2 className="text-sm font-medium text-white/80">Live Agent Stream</h2>
                {isScanning && (
                  <div className="ml-auto flex items-center gap-3 text-xs text-white/50">
                    <span className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                      {batchProgress.total > 1 ? `${batchProgress.current}/${batchProgress.total}` : 'Running'}
                    </span>
                    <button type="button" onClick={cancelScan} title="Cancel scan" aria-label="Cancel scan" className="p-1 hover:text-white">
                      <Square className="h-3.5 w-3.5" />
                    </button>
                  </div>
                )}
              </div>
              
              <div className="flex-1 p-6 overflow-y-auto">
                <AgentFeed events={events} selectedFunc={selectedFunc} />
              </div>
            </motion.div>
          </div>
        </div>

        {/* Analytics */}
        <motion.section
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mt-6 flex flex-col gap-6"
        >
          <div className="flex items-center gap-3">
            <BarChart3 className="w-5 h-5 text-white/50" />
            <h2 className="text-sm font-medium text-white/80">Evaluation Analytics</h2>
          </div>

          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <MetricCard label="Scans" value={String(metrics.total_scans)} />
            <MetricCard label="Vulnerabilities found" value={String(metrics.vulnerabilities_found)} />
            <MetricCard label="Patches validated" value={String(metrics.patches_validated)} />
            <MetricCard
              label="Patch success"
              value={`${Math.round((metrics.patch_rate ?? 0) * 100)}%`}
              highlight
            />
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            <ModelHealthCard title="Detection recall" value={modelHealth.recall} color="blue" />
            <ModelHealthCard title="Triage precision" value={modelHealth.precision} color="green" />
            <ModelHealthCard title="Patch success rate" value={modelHealth.patch_success_rate} color="amber" />
          </div>

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <div className="glassmorphism rounded-3xl p-6">
              <h3 className="mb-4 text-sm font-medium text-white/70">Judge verdicts</h3>
              {verdictEntries.length === 0 ? (
                <p className="text-sm text-white/35">No completed scans yet.</p>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {verdictEntries.map(([verdict, count]) => (
                    <span
                      key={verdict}
                      className={cn(
                        'rounded-full border px-3 py-1 text-xs',
                        verdict === 'PASS'
                          ? 'border-green-500/30 bg-green-500/10 text-green-300'
                          : verdict === 'FAIL'
                            ? 'border-red-500/30 bg-red-500/10 text-red-300'
                            : 'border-white/15 bg-white/5 text-white/60'
                      )}
                    >
                      {verdict}: {count}
                    </span>
                  ))}
                </div>
              )}
            </div>

            <div className="glassmorphism rounded-3xl p-6">
              <div className="mb-4 flex items-center justify-between gap-3">
                <h3 className="text-sm font-medium text-white/70">Recent validated fixes</h3>
                <span className="text-xs text-white/35">{fixes.length} shown</span>
              </div>
              {dataError && <p className="mb-3 text-xs text-red-300">{dataError}</p>}
              {fixes.length === 0 ? (
                <p className="text-sm text-white/35">No validated patches yet.</p>
              ) : (
                <div className="space-y-3">
                  {fixes.map((fix) => (
                    <div key={fix.scan_id} className="flex items-start justify-between gap-3 text-xs">
                      <div className="min-w-0">
                        <div className="truncate text-white/70">{fix.function_id}</div>
                        <div className="truncate text-white/35">{fix.file_path}</div>
                      </div>
                      <div className="shrink-0 text-right font-mono text-white/40">
                        <div>{fix.vulnerability_type || '—'}</div>
                        <div>{fix.severity || '—'}</div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          <div className="glassmorphism rounded-3xl p-6">
            <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
              <div>
                <h3 className="text-sm font-medium text-white/70">Generated figures</h3>
                <p className="text-xs text-white/35">
                  {evaluation?.evaluation_json_exists
                    ? `${figures.length} figure${figures.length === 1 ? '' : 's'} in ${evaluation.figures_dir}`
                    : 'No evaluation run yet.'}
                </p>
              </div>
              <button
                type="button"
                onClick={runEvaluation}
                disabled={runningEvaluation}
                className="flex items-center gap-2 rounded-lg border border-white/15 bg-white/5 px-3 py-1.5 text-xs text-white/70 hover:bg-white/10 hover:text-white disabled:cursor-not-allowed disabled:opacity-50"
              >
                <RefreshCw className={cn('h-3.5 w-3.5', runningEvaluation && 'animate-spin')} />
                {runningEvaluation ? 'Running evaluation' : 'Re-run evaluation'}
              </button>
            </div>

            {evaluationError && (
              <div className="mb-4 flex items-start gap-2 text-sm text-red-300">
                <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{evaluationError}</span>
              </div>
            )}

            {figures.length > 0 ? (
              <div className="grid grid-cols-2 gap-4 md:grid-cols-3 lg:grid-cols-5">
                {figures.map((name) => (
                  <a
                    key={name}
                    href={`${API}/api/evaluation/figures/${name}`}
                    target="_blank"
                    rel="noreferrer"
                    className="group overflow-hidden rounded-2xl border border-white/10 bg-white/5"
                  >
                    <img
                      src={`${API}/api/evaluation/figures/${name}`}
                      alt={name}
                      className="h-24 w-full object-cover transition-transform group-hover:scale-105"
                    />
                    <span className="block truncate p-2 text-[11px] text-white/50">{name}</span>
                  </a>
                ))}
              </div>
            ) : (
              <p className="text-sm text-white/35">
                Run the evaluation to render the labeled figures into data/benchmarks.
              </p>
            )}
          </div>
        </motion.section>
      </div>
    </div>
  );
}
