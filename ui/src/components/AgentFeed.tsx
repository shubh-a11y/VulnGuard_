import { motion, AnimatePresence } from 'framer-motion';
import { ShieldAlert, Wrench, Scale, Terminal, Download, Network, AlertCircle, RefreshCw } from 'lucide-react';
import { cn } from '../lib/utils';

interface RedAgentState {
  pipeline_status?: string;
  vulnerability_found?: boolean;
  exploit_harness?: string | null;
  exploit_status?: string;
  exploit_error?: string | null;
  error_logs?: string | null;
  red_report?: {
    parse_error?: string;
    raw?: string;
    vulnerability_type?: string | null;
    severity?: string | null;
    explanation?: string | null;
  } | null;
}

interface BlueAgentState {
  pipeline_status?: string;
  patched_code?: string | null;
  patch_diff?: string | null;
  patch_justification?: string | null;
  error_logs?: string | null;
}

interface JudgeAgentState {
  pipeline_status?: string;
  judge_verdict?: string;
  error_logs?: string | null;
  attempt_number?: number;
  max_attempts?: number;
}

const STAGE_LABELS: Record<string, string> = {
  startup: 'Request',
  triage: 'ML triage',
  context: 'Context gathering',
  agents: 'Agent pipeline',
  red_agent: 'Red Agent',
  blue_agent: 'Blue Agent',
  judge_agent: 'Judge Agent',
  stream: 'Live stream',
  complete: 'Finalization',
};

const stageLabel = (stage?: string) => (stage && STAGE_LABELS[stage]) || stage || 'Unknown stage';

export default function AgentFeed({ events, selectedFunc }: { events: any[], selectedFunc: any }) {
  const triageCompleted = events.some((ev) => ev.type === 'triage_result');

  const downloadPatch = (state: any) => {
    const content = state.patch_diff || state.patched_code;
    if (!content) return;
    const url = URL.createObjectURL(new Blob([content], { type: 'text/plain' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = `${selectedFunc?.name || 'vulnguard-fix'}.patch`;
    link.click();
    URL.revokeObjectURL(url);
  };

  if (!selectedFunc) {
    return (
      <div className="flex h-full items-center justify-center text-white/30">
        <div className="flex flex-col items-center gap-4">
          <Terminal className="w-12 h-12" />
          <p>Select a function to begin analysis</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">

      <AnimatePresence>
        {events.map((ev, i) => (
          <motion.div
            key={i}
            initial={{ opacity: 0, y: 10, filter: 'blur(10px)' }}
            animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
            className="flex flex-col gap-2"
          >
            {ev.type === 'batch_function' && (
              <div className="border-b border-white/10 pb-2 text-xs font-medium text-white/40">
                {ev.relative_path} / {ev.function_name}
              </div>
            )}

            {ev.type === 'status' && (
              <div className="flex items-center gap-2 text-sm text-white/50 font-mono">
                <span className="text-white/30">{'>'}</span> {ev.message}
              </div>
            )}

            {ev.type === 'triage_result' && (
              <div className="glassmorphism p-4 rounded-2xl flex items-center justify-between border-white/5">
                <div>
                  <h3 className="text-sm text-white/60 uppercase tracking-wider mb-1">ML Triage Score</h3>
                  <div className="text-2xl font-mono">
                    <span className={cn(ev.is_high_risk ? "text-red-400" : "text-green-400")}>{ev.score}</span>
                    <span className="text-white/30 text-lg">/100</span>
                  </div>
                </div>
                {ev.is_high_risk && (
                  <div className="px-3 py-1 bg-red-500/10 text-red-400 border border-red-500/20 rounded-full text-xs font-medium animate-pulse">
                    HIGH RISK DETECTED
                  </div>
                )}
              </div>
            )}

            {ev.type === 'context_result' && (
              <div className="flex items-center gap-3 text-sm text-white/60">
                <Network className="h-4 w-4" />
                <span>{ev.imports} imports, {ev.callees} callees, {ev.token_count} context tokens</span>
              </div>
            )}

            {ev.type === 'agent_update' && ev.agent === 'red_agent' && (() => {
              const state: RedAgentState = ev.state ?? {};
              const parseError =
                state.pipeline_status === 'RED_ERROR' || state.red_report?.parse_error;

              if (parseError) {
                return (
                  <div className="glassmorphism p-5 rounded-2xl border-red-500/40 bg-red-950/20 relative overflow-hidden">
                    <div className="flex items-center gap-3 mb-3">
                      <div className="p-2 bg-red-500/20 text-red-300 rounded-lg"><AlertCircle className="w-5 h-5" /></div>
                      <h3 className="font-semibold text-red-200">Red Agent: Response Error</h3>
                    </div>
                    <p className="text-white/70 text-sm pl-11">
                      The agent's analysis could not be read. This is an internal failure,
                      not a confirmed absence of vulnerabilities.
                    </p>
                    {(state.red_report?.parse_error || state.error_logs) && (
                      <div className="mt-3 ml-11 bg-black/50 p-3 rounded-xl border border-red-500/20 overflow-x-auto">
                        <code className="text-xs text-red-300 whitespace-pre-wrap">
                          {state.red_report?.parse_error || state.error_logs}
                        </code>
                      </div>
                    )}
                  </div>
                );
              }

              if (state.vulnerability_found && !state.exploit_harness) {
                return (
                  <div
                    className="glassmorphism p-5 rounded-2xl border-amber-500/30 bg-amber-950/10 relative overflow-hidden"
                    data-testid="red-diagnosis-no-exploit"
                  >
                    <div className="flex items-center gap-3 mb-3">
                      <div className="p-2 bg-amber-500/20 text-amber-300 rounded-lg"><ShieldAlert className="w-5 h-5" /></div>
                      <h3 className="font-semibold text-amber-200">Red Agent: Defect Diagnosed, Exploit Unavailable</h3>
                    </div>
                    <p className="text-white/70 text-sm pl-11">
                      The diagnosis was preserved, but no usable proof of concept could be
                      generated. The patch cannot be proven secure without one.
                    </p>
                    {state.exploit_error && (
                      <div className="mt-3 ml-11 bg-black/50 p-3 rounded-xl border border-amber-500/20 overflow-x-auto">
                        <code className="text-xs text-amber-200 whitespace-pre-wrap">{state.exploit_error}</code>
                      </div>
                    )}
                  </div>
                );
              }

              if (state.vulnerability_found) {
                return (
                  <div className="glassmorphism p-5 rounded-2xl border-red-500/20 bg-red-950/20 relative overflow-hidden group">
                    <div className="absolute top-0 right-0 w-32 h-32 bg-red-500/10 blur-[50px] -mr-10 -mt-10 transition-opacity"></div>
                    <div className="flex items-center gap-3 mb-4">
                      <div className="p-2 bg-red-500/20 text-red-400 rounded-lg"><ShieldAlert className="w-5 h-5" /></div>
                      <h3 className="font-semibold text-red-200">Red Agent Attack Payload</h3>
                    </div>
                    <div className="bg-black/50 p-4 rounded-xl border border-white/5 overflow-x-auto">
                      <code className="text-sm text-red-300 whitespace-pre">{state.exploit_harness || state.error_logs}</code>
                    </div>
                    {state.exploit_harness && (
                      <p className="mt-3 text-xs text-white/40 pl-11">
                        Exploit generated — awaiting sandbox validation.
                      </p>
                    )}
                  </div>
                );
              }

              return (
                <div className="glassmorphism p-5 rounded-2xl border-green-500/20 bg-green-950/20 relative overflow-hidden group">
                  <div className="absolute top-0 right-0 w-32 h-32 bg-green-500/10 blur-[50px] -mr-10 -mt-10 transition-opacity"></div>
                  <div className="flex items-center gap-3">
                    <div className="p-2 bg-green-500/20 text-green-400 rounded-lg"><ShieldAlert className="w-5 h-5" /></div>
                    <h3 className="font-semibold text-green-200">Red Agent: No Vulnerability Detected</h3>
                  </div>
                  <p className="text-white/70 text-sm mt-3 pl-11">The agent analyzed the function and found no exploitable defect.</p>
                </div>
              );
            })()}

            {ev.type === 'agent_update' && ev.agent === 'blue_agent' && (() => {
              const state: BlueAgentState = ev.state ?? {};

              if (state.pipeline_status === 'BLUE_ERROR' && !state.patched_code) {
                return (
                  <div className="glassmorphism p-5 rounded-2xl border-red-500/40 bg-red-950/20 relative overflow-hidden">
                    <div className="flex items-center gap-3 mb-3">
                      <div className="p-2 bg-red-500/20 text-red-300 rounded-lg"><AlertCircle className="w-5 h-5" /></div>
                      <h3 className="font-semibold text-red-200">Blue Agent: Patch Generation Error</h3>
                    </div>
                    <p className="text-white/70 text-sm pl-11">
                      The agent could not produce a valid patch response.
                    </p>
                    {state.error_logs && (
                      <div className="mt-3 ml-11 bg-black/50 p-3 rounded-xl border border-red-500/20 overflow-x-auto">
                        <code className="text-xs text-red-300 whitespace-pre-wrap">{state.error_logs}</code>
                      </div>
                    )}
                  </div>
                );
              }

              if (!state.patched_code) return null;

              return (
                <div className="glassmorphism p-5 rounded-2xl border-blue-500/20 bg-blue-950/20 relative overflow-hidden">
                   <div className="absolute top-0 right-0 w-32 h-32 bg-blue-500/10 blur-[50px] -mr-10 -mt-10 transition-opacity"></div>
                  <div className="flex items-center gap-3 mb-4">
                    <div className="p-2 bg-blue-500/20 text-blue-400 rounded-lg"><Wrench className="w-5 h-5" /></div>
                    <h3 className="font-semibold text-blue-200">Blue Agent PATCH_GENERATED</h3>
                    <button
                      type="button"
                      onClick={() => downloadPatch(state)}
                      className="ml-auto p-2 text-blue-300 hover:text-white"
                      title="Download patch"
                      aria-label="Download patch"
                    >
                      <Download className="h-4 w-4" />
                    </button>
                  </div>
                  <div className="bg-black/50 p-4 rounded-xl border border-white/5 overflow-x-auto">
                    <code className="text-sm text-blue-300 whitespace-pre">{state.patch_diff || state.patched_code}</code>
                  </div>
                  {state.patch_justification && (
                    <p className="mt-3 text-sm text-white/60">{state.patch_justification}</p>
                  )}
                  <p className="mt-2 text-xs text-white/40">Patch generated — awaiting sandbox validation.</p>
                </div>
              );
            })()}

            {ev.type === 'agent_update' && ev.agent === 'judge_agent' && (() => {
              const state: JudgeAgentState = ev.state ?? {};
              const isRetry = state.pipeline_status === 'RETRY';
              const attempt = (state.attempt_number ?? 0) + 1;
              const maxAttempts = state.max_attempts ?? 3;

              return (
                <div className={cn(
                  'glassmorphism p-5 rounded-2xl relative overflow-hidden',
                  isRetry ? 'border-orange-500/30 bg-orange-950/10' : 'border-yellow-500/20 bg-yellow-950/10',
                )}>
                  <div className="flex items-center gap-3 mb-2">
                    <div className={cn('p-2 rounded-lg', isRetry ? 'bg-orange-500/20 text-orange-300' : 'bg-yellow-500/20 text-yellow-400')}>
                      {isRetry ? <RefreshCw className="w-5 h-5" /> : <Scale className="w-5 h-5" />}
                    </div>
                    <h3 className={cn('font-semibold', isRetry ? 'text-orange-200' : 'text-yellow-200')}>
                      {isRetry ? 'Validation Failed — Retry Scheduled' : 'Judge Agent Verdict'}
                    </h3>
                  </div>
                  <p className="text-white/80 pl-11 mb-2">
                    Verdict: <span className="font-bold text-white">{state.judge_verdict}</span>
                    {isRetry && (
                      <span className="text-white/50 font-normal"> — retry {attempt}/{maxAttempts} in progress</span>
                    )}
                  </p>
                  {state.error_logs && (
                    <div className="mt-2 ml-11 bg-black/50 p-3 rounded-xl border border-red-500/20 overflow-x-auto">
                      <code className="text-sm text-red-300 whitespace-pre-wrap">{state.error_logs}</code>
                    </div>
                  )}
                </div>
              );
            })()}

            {ev.type === 'error' && (
              <div
                className="glassmorphism p-5 rounded-2xl border-red-500/50 bg-red-950/20 relative overflow-hidden"
                data-testid="pipeline-error"
              >
                <div className="mb-2 flex items-center gap-3">
                  <h3 className="text-red-400 font-bold">Agent Pipeline Error</h3>
                  <span className="ml-auto rounded-full border border-red-500/30 bg-red-500/10 px-2 py-0.5 text-xs text-red-200">
                    {stageLabel(ev.stage)}
                  </span>
                </div>
                {triageCompleted && (
                  <p className="mb-2 text-xs text-white/50">
                    ML triage completed and its score above is still valid — this failure
                    happened in a later stage, not in triage.
                  </p>
                )}
                <code className="text-red-300 text-sm whitespace-pre-wrap">{ev.message}</code>
              </div>
            )}

            {ev.type === 'complete' && ev.pipeline_status && (
              <div className="flex items-center gap-2 text-xs font-mono text-white/40">
                <span>scan finished:</span>
                <span className="text-white/60">{ev.pipeline_status}</span>
                {ev.judge_verdict && <span className="text-white/40">/ {ev.judge_verdict}</span>}
              </div>
            )}

          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
}
