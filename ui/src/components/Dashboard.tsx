import { useEffect, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import {
  Shield,
  Upload,
  Activity,
  Code,
  TerminalSquare,
  AlertCircle,
  Play,
  Square,
  BarChart3,
  RefreshCw,
  Trash2,
  History,
} from 'lucide-react';
import { cn } from '../lib/utils';
import AgentFeed from './AgentFeed';
import {
  clearStoredOutputs,
  deleteStoredOutput,
  loadStoredOutputs,
  saveStoredOutput,
  type StoredScanOutput,
} from '../lib/scanOutputStore';
import {
  applyEventToStreams,
  createStream,
  streamFromStoredOutput,
  streamKey,
  upsertStream,
  type FunctionStream,
} from '../lib/functionStreams';
import { MetricCard, ModelHealthCard } from './dashboard/MetricCards';

const API = 'http://localhost:8000';
const WS = 'ws://localhost:8000/ws/scan';

// Functions in a batch scan run with a small amount of concurrency; each one
// keeps its own socket and its own card in the live stream.
const BATCH_CONCURRENCY = 3;

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

const newScanId = () => {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
};

export default function Dashboard() {
  const [file, setFile] = useState<File | null>(null);
  const [functions, setFunctions] = useState<any[]>([]);
  const [selectedFuncId, setSelectedFuncId] = useState<string | null>(null);
  const [streams, setStreams] = useState<FunctionStream[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [uploadError, setUploadError] = useState('');
  const [metrics, setMetrics] = useState<Metrics>({ total_scans: 0, vulnerabilities_found: 0, patches_validated: 0 });
  const [history, setHistory] = useState<any[]>([]);
  const [batchProgress, setBatchProgress] = useState({ current: 0, total: 0 });
  const [verdicts, setVerdicts] = useState<Record<string, number>>({});
  const [modelHealth, setModelHealth] = useState<ModelHealth>({ recall: 0, precision: 0, patch_success_rate: 0 });
  const [evaluation, setEvaluation] = useState<EvaluationHealth | null>(null);
  const [storedOutputs, setStoredOutputs] = useState<StoredScanOutput[]>([]);
  const [runningEvaluation, setRunningEvaluation] = useState(false);
  const [evaluationError, setEvaluationError] = useState('');
  const wsRegistry = useRef<Map<string, WebSocket>>(new Map());
  const sessionRef = useRef('');
  const cancelledRef = useRef(false);

  const loadDashboardData = async () => {
    const requests = [
      fetch(`${API}/api/metrics`),
      fetch(`${API}/api/scan/status`),
      fetch(`${API}/api/scan/verdict-distribution`),
      fetch(`${API}/api/evaluation/model-health`),
      fetch(`${API}/api/evaluation/health`),
    ];
    const [metricsRes, scansRes, verdictRes, healthRes, evaluationRes] = await Promise.allSettled(requests);
    try {
      if (metricsRes.status === 'fulfilled' && metricsRes.value.ok) setMetrics(await metricsRes.value.json());
      if (scansRes.status === 'fulfilled' && scansRes.value.ok) {
        const data = await scansRes.value.json();
        setHistory(Object.values(data.scans).slice(0, 5));
      }
      if (verdictRes.status === 'fulfilled' && verdictRes.value.ok) setVerdicts(await verdictRes.value.json());
      if (healthRes.status === 'fulfilled' && healthRes.value.ok) setModelHealth(await healthRes.value.json());
      if (evaluationRes.status === 'fulfilled' && evaluationRes.value.ok) setEvaluation(await evaluationRes.value.json());
    } catch {
      // The scan workflow reports connection errors where the user acts on them.
    }
  };

  useEffect(() => {
    loadDashboardData();
    const stored = loadStoredOutputs();
    setStoredOutputs(stored);
    if (stored.length > 0) {
      // Keep the most recent output visible after a reload instead of an empty feed.
      const restored = streamFromStoredOutput(stored[0]);
      setStreams([restored]);
      setSelectedFuncId(restored.functionId);
    }
  }, []);

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files?.[0]) return;
    const uploadedFile = e.target.files[0];
    setFile(uploadedFile);
    setFunctions([]);
    setSelectedFuncId(null);
    setUploadError('');

    // A new target means a new live session; finished output stays in storage.
    wsRegistry.current.forEach((ws) => {
      try {
        ws.close();
      } catch {
        // The socket is already gone; nothing to clean up.
      }
    });
    wsRegistry.current.clear();
    sessionRef.current = '';
    setStreams([]);

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

  const runScan = (func: any, scanId: string) =>
    new Promise<void>((resolve) => {
      const functionId = func.id ?? func.name;
      const key = streamKey(scanId, functionId);
      const startedAt = new Date().toISOString();
      const collected: any[] = [];

      // Reuse the card if this function already has one in this scan, so the
      // list order never changes mid-batch.
      setStreams((prev) => {
        if (prev.some((stream) => stream.key === key)) {
          return prev.map((stream) =>
            stream.key === key ? { ...stream, status: 'RUNNING', updatedAt: startedAt } : stream,
          );
        }
        return upsertStream(
          prev,
          createStream({
            scanId,
            functionId,
            functionName: func.name,
            relativePath: func.relative_path ?? '',
            startedAt,
          }),
        );
      });

      const append = (event: any) => {
        collected.push(event);
        setStreams((prev) => applyEventToStreams(prev, key, event));
      };

      append({
        type: 'status',
        stage: 'startup',
        function_id: functionId,
        message: `Starting scan for ${func.name}...`,
      });

      const ws = new WebSocket(WS);
      wsRegistry.current.set(key, ws);
      let finished = false;
      let terminalSeen = false;

      const finish = () => {
        if (finished) return;
        finished = true;
        wsRegistry.current.delete(key);
        const terminal = [...collected]
          .reverse()
          .find((event) => event.type === 'complete' || event.type === 'error');
        const output: StoredScanOutput = {
          id: key,
          functionId,
          functionName: func.name,
          relativePath: func.relative_path ?? '',
          startedAt,
          finishedAt: new Date().toISOString(),
          pipelineStatus:
            terminal?.pipeline_status ?? (terminal?.type === 'error' ? 'ERROR' : 'INCOMPLETE'),
          judgeVerdict: terminal?.judge_verdict,
          events: collected,
        };
        if (collected.length > 0) setStoredOutputs(saveStoredOutput(output));
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
            function_id: functionId,
            message: 'Received a malformed event from the backend.',
          };
        }
        append(data);
        if (data.type === 'complete' || data.type === 'error') {
          terminalSeen = true;
          ws.close();
          finish();
        }
      };

      ws.onerror = () => {
        // Pipeline failures already arrive as an `error` event; a close after
        // that is expected, so don't append a second, misleading connection error.
        if (!terminalSeen) {
          append({
            type: 'error',
            stage: 'stream',
            function_id: functionId,
            message: 'WebSocket connection failed',
          });
        }
        finish();
      };
      ws.onclose = finish;
    });

  const startScan = async (func: any) => {
    cancelledRef.current = false;
    if (!sessionRef.current) sessionRef.current = newScanId();
    setSelectedFuncId(func.id ?? func.name);
    setIsScanning(true);
    setBatchProgress({ current: 1, total: 1 });
    await runScan(func, sessionRef.current);
    setIsScanning(false);
    setBatchProgress({ current: 0, total: 0 });
    loadDashboardData();
  };

  const startBatchScan = async () => {
    cancelledRef.current = false;
    const scanId = newScanId();
    sessionRef.current = scanId;
    setIsScanning(true);
    // Every discovered function gets its card before any agent starts, so all
    // queued work is visible at once.
    setStreams(
      functions.map((func) =>
        createStream({
          scanId,
          functionId: func.id ?? func.name,
          functionName: func.name,
          relativePath: func.relative_path ?? '',
        }),
      ),
    );
    setBatchProgress({ current: 0, total: functions.length });

    const queue = [...functions];
    let completed = 0;
    const worker = async () => {
      while (!cancelledRef.current && queue.length > 0) {
        const func = queue.shift();
        if (!func) break;
        await runScan(func, scanId);
        completed += 1;
        setBatchProgress({ current: completed, total: functions.length });
      }
    };
    const workerCount = Math.max(1, Math.min(BATCH_CONCURRENCY, functions.length));
    await Promise.all(Array.from({ length: workerCount }, () => worker()));

    setIsScanning(false);
    setBatchProgress({ current: 0, total: 0 });
    loadDashboardData();
  };

  const cancelScan = () => {
    cancelledRef.current = true;
    wsRegistry.current.forEach((ws) => {
      try {
        ws.close();
      } catch {
        // Already closed.
      }
    });
    wsRegistry.current.clear();
    const now = new Date().toISOString();
    setStreams((prev) =>
      prev.map((stream) =>
        stream.terminal
          ? stream
          : {
              ...stream,
              terminal: true,
              pipelineStatus: 'CANCELLED',
              status: 'INCONCLUSIVE' as const,
              updatedAt: now,
            },
      ),
    );
    setIsScanning(false);
    setBatchProgress({ current: 0, total: 0 });
  };

  const clearStreams = () => {
    wsRegistry.current.forEach((ws) => {
      try {
        ws.close();
      } catch {
        // Already closed.
      }
    });
    wsRegistry.current.clear();
    setStreams([]);
    setSelectedFuncId(null);
  };

  const openStoredOutput = (run: StoredScanOutput) => {
    const restored = streamFromStoredOutput(run);
    setStreams((prev) => upsertStream(prev, restored));
    setSelectedFuncId(restored.functionId);
  };

  const removeStoredOutput = (id: string) => {
    setStoredOutputs(deleteStoredOutput(id));
  };

  const removeAllStoredOutputs = () => {
    clearStoredOutputs();
    setStoredOutputs([]);
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
                          selectedFuncId === (f.id ?? f.name)
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

              {storedOutputs.length > 0 && (
                <div className="mt-6 border-t border-white/10 pt-4">
                  <div className="mb-3 flex items-center justify-between gap-3">
                    <h3 className="flex items-center gap-1.5 text-xs font-medium text-white/40">
                      <History className="h-3.5 w-3.5" /> Stored output ({storedOutputs.length})
                    </h3>
                    <button
                      type="button"
                      onClick={removeAllStoredOutputs}
                      disabled={isScanning}
                      className="text-xs text-red-300/80 hover:text-red-200 disabled:cursor-not-allowed disabled:opacity-40"
                    >
                      Delete all
                    </button>
                  </div>
                  <div className="max-h-56 space-y-2 overflow-y-auto pr-1">
                    {storedOutputs.map((run) => (
                      <div
                        key={run.id}
                        className="flex items-center gap-2 rounded-lg border border-white/10 bg-white/5 p-2 text-xs"
                      >
                        <button
                          type="button"
                          onClick={() => openStoredOutput(run)}
                          disabled={isScanning}
                          title="Open stored output"
                          className="min-w-0 flex-1 text-left hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
                        >
                          <span className="block truncate text-white/70">{run.functionName}</span>
                          <span className="block truncate text-white/35">
                            {run.judgeVerdict || run.pipelineStatus || 'stored'} ·{' '}
                            {new Date(run.finishedAt || run.startedAt).toLocaleString()}
                          </span>
                        </button>
                        <button
                          type="button"
                          onClick={() => removeStoredOutput(run.id)}
                          disabled={isScanning}
                          title="Delete stored output"
                          aria-label="Delete stored output"
                          className="shrink-0 p-1 text-white/40 hover:text-red-300 disabled:cursor-not-allowed disabled:opacity-40"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </motion.div>
          </div>

          {/* Agent Live Stream — its own full-width row so every function card
              and every vertical section gets the whole page width. */}
          <div className="lg:col-span-12 flex min-w-0 flex-col gap-6">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="glassmorphism rounded-3xl p-0 overflow-hidden flex flex-col h-[700px]"
            >
              <div className="p-4 border-b border-white/10 bg-white/5 flex flex-wrap items-center gap-3">
                <TerminalSquare className="w-5 h-5 text-white/50" />
                <h2 className="text-sm font-medium text-white/80">Live Agent Stream</h2>
                <span className="text-xs text-white/35">
                  {streams.length} function{streams.length === 1 ? '' : 's'}
                </span>
                <div className="ml-auto flex items-center gap-3 text-xs text-white/50">
                  {isScanning && (
                    <span className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
                      {batchProgress.total > 1
                        ? `${batchProgress.current}/${batchProgress.total}`
                        : 'Running'}
                    </span>
                  )}
                  {streams.length > 0 && (
                    <button
                      type="button"
                      onClick={clearStreams}
                      className="flex items-center gap-1 hover:text-white"
                      title="Clear the live stream"
                    >
                      <Trash2 className="h-3.5 w-3.5" /> Clear
                    </button>
                  )}
                  {isScanning && (
                    <button type="button" onClick={cancelScan} title="Cancel scan" aria-label="Cancel scan" className="p-1 hover:text-white">
                      <Square className="h-3.5 w-3.5" />
                    </button>
                  )}
                </div>
              </div>

              <div className="flex-1 overflow-hidden">
                <AgentFeed streams={streams} />
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

          <div className="grid grid-cols-1 gap-6">
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
