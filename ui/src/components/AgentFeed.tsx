import { useEffect, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldAlert,
  Wrench,
  Scale,
  Terminal,
  Download,
  Network,
  AlertCircle,
  RefreshCw,
  ArrowDown,
  Cpu,
  FileCode,
  PlayCircle,
} from 'lucide-react';
import { cn } from '../lib/utils';
import type { FunctionStream, StreamStatus } from '../lib/functionStreams';

const STATUS_STYLES: Record<StreamStatus, string> = {
  QUEUED: 'border-white/15 bg-white/5 text-white/50',
  RUNNING: 'border-sky-500/30 bg-sky-500/10 text-sky-300',
  RETRYING: 'border-orange-500/30 bg-orange-500/10 text-orange-300',
  COMPLETED: 'border-white/20 bg-white/10 text-white/70',
  PASS: 'border-green-500/30 bg-green-500/10 text-green-300',
  FAIL: 'border-red-500/30 bg-red-500/10 text-red-300',
  INCONCLUSIVE: 'border-amber-500/30 bg-amber-500/10 text-amber-300',
};

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

const flagText = (value?: boolean) =>
  value === undefined || value === null ? 'not reported' : value ? 'yes' : 'no';

function StatusChip({ status }: { status: StreamStatus }) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-medium',
        STATUS_STYLES[status],
      )}
    >
      {status === 'RUNNING' && <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-current" />}
      {status === 'RETRYING' && <RefreshCw className="h-3 w-3" />}
      {status}
    </span>
  );
}

function CodeBlock({
  value,
  tone = 'text-white/80',
  maxHeight = 'max-h-64',
}: {
  value?: string | null;
  tone?: string;
  maxHeight?: string;
}) {
  if (!value) return null;
  return (
    <div
      className={cn(
        'w-full overflow-auto rounded-xl border border-white/5 bg-black/50 p-3',
        maxHeight,
      )}
    >
      <code className={cn('block whitespace-pre text-xs leading-relaxed', tone)}>{value}</code>
    </div>
  );
}

type SectionStage = 'waiting' | 'running' | 'complete';

const STAGE_BADGES: Record<SectionStage, { label: string; className: string }> = {
  waiting: { label: 'waiting', className: 'border-white/10 bg-white/5 text-white/35' },
  running: { label: 'running', className: 'border-sky-500/30 bg-sky-500/10 text-sky-300' },
  complete: { label: 'complete', className: 'border-green-500/25 bg-green-500/10 text-green-300' },
};

function StageBadge({ stage }: { stage: SectionStage }) {
  const badge = STAGE_BADGES[stage];
  return (
    <span
      data-testid={`stage-${stage}`}
      className={cn('rounded-full border px-2 py-0.5 text-[10px] uppercase tracking-wider', badge.className)}
    >
      {badge.label}
    </span>
  );
}

function SectionShell({
  title,
  icon,
  accent,
  children,
  actions,
  testId,
  stage,
}: {
  title: string;
  icon: React.ReactNode;
  accent: string;
  children: React.ReactNode;
  actions?: React.ReactNode;
  testId?: string;
  stage?: SectionStage;
}) {
  return (
    <section data-testid={testId} className={cn('w-full min-w-0 rounded-2xl border p-4', accent)}>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        {icon}
        <h4 className="text-xs font-semibold uppercase tracking-wider text-white/70">{title}</h4>
        {stage && <StageBadge stage={stage} />}
        {actions && <div className="ml-auto">{actions}</div>}
      </div>
      {children}
    </section>
  );
}

/** Progress of one agent section, derived only from events already received. */
const stageOf = (record: Record<string, any> | null): SectionStage => {
  if (!record) return 'waiting';
  if (record.completed) return 'complete';
  if (record.started) return 'running';
  return 'waiting';
};

function Placeholder({ text }: { text: string }) {
  return <p className="text-xs text-white/35">{text}</p>;
}

const FEATURE_LABELS: Record<string, string> = {
  loc: 'lines of code',
  cyclomatic_complexity: 'cyclomatic complexity',
  ast_max_depth: 'AST depth',
  parameter_count: 'parameters',
  maintainability_index: 'maintainability index',
  nested_block_depth: 'nesting depth',
  is_template: 'template code',
  unsafe_func_count: 'unsafe C functions',
  memory_op_count: 'memory operations',
  input_func_count: 'input sources',
  pointer_arith_count: 'pointer arithmetic',
  unchecked_return_count: 'unchecked returns',
  string_op_count: 'string operations',
};

const featureLabel = (name: string) => FEATURE_LABELS[name] ?? name.replace(/_/g, ' ');

const featureValue = (value: number) =>
  Number.isInteger(value) ? String(value) : value.toFixed(2);

function TriageSection({ stream }: { stream: FunctionStream }) {
  const triage = stream.triage;

  return (
    <SectionShell
      title="ML Triage"
      icon={<Cpu className="h-4 w-4 text-white/60" />}
      accent="border-white/15 bg-white/5"
      testId="section-ml-triage"
    >
      {!triage ? (
        <Placeholder text="Awaiting ML triage." />
      ) : (
        <div className="flex flex-col gap-4 sm:flex-row sm:gap-6">
          <div className="shrink-0 sm:w-48">
            <div className="flex items-baseline gap-1 font-mono">
              <span
                className={cn(
                  'text-3xl font-semibold',
                  triage.isHighRisk ? 'text-red-300' : 'text-green-300',
                )}
              >
                {triage.score}
              </span>
              <span className="text-xs text-white/35">/100</span>
            </div>
            <div
              className={cn(
                'mt-1 inline-flex rounded-full border px-2 py-0.5 text-[11px]',
                triage.isHighRisk
                  ? 'border-red-500/20 bg-red-500/10 text-red-300'
                  : 'border-green-500/20 bg-green-500/10 text-green-300',
              )}
            >
              {triage.isHighRisk ? 'HIGH RISK' : 'BELOW THRESHOLD'}
            </div>
            {triage.threshold !== undefined && (
              <p className="mt-2 text-[11px] text-white/35">
                threshold {triage.threshold}/100
              </p>
            )}
            {triage.staticSignal && (
              <p
                data-testid="triage-static-signal"
                className="mt-1 break-words text-[11px] text-amber-300/80"
              >
                static signal: {triage.staticSignal.replace(/_/g, ' ').toLowerCase()}
              </p>
            )}
          </div>

          <div className="min-w-0 flex-1">
            {triage.features.length > 0 ? (
              <dl className="grid grid-cols-1 gap-x-6 text-[11px] sm:grid-cols-2">
                {triage.features.map((feature) => (
                  <div
                    key={feature.name}
                    className="flex items-baseline justify-between gap-3 border-b border-white/5 py-1"
                  >
                    <dt className="truncate text-white/40">{featureLabel(feature.name)}</dt>
                    <dd className="shrink-0 font-mono text-white/70">
                      {featureValue(feature.value)}
                    </dd>
                  </div>
                ))}
              </dl>
            ) : (
              <p className="text-xs text-white/35">
                No extracted features reported (the score came from a static signal or the
                model was unavailable).
              </p>
            )}
          </div>
        </div>
      )}
    </SectionShell>
  );
}

function DiagnosisDetails({ state }: { state: Record<string, any> }) {
  const rows: Array<[string, unknown]> = [
    ['Classification', state.vulnerability_type],
    ['CWE', state.cwe_id],
    ['Severity', state.severity],
    ['Location', state.location],
    ['Affected lines', Array.isArray(state.affected_lines) ? state.affected_lines.join(', ') : state.affected_lines],
    ['Attack strategy', state.attack_strategy],
    ['Explanation', state.explanation],
    ['Confidence', typeof state.confidence === 'number' ? state.confidence.toFixed(2) : state.confidence],
  ];
  const present = rows.filter(([, value]) => value !== null && value !== undefined && value !== '');
  if (present.length === 0) return null;
  return (
    <dl className="mb-3 grid grid-cols-1 gap-1.5 text-xs">
      {present.map(([label, value]) => (
        <div key={label} className="flex gap-2">
          <dt className="w-28 shrink-0 text-white/35 sm:w-32">{label}</dt>
          <dd className="min-w-0 break-words text-white/70">{String(value)}</dd>
        </div>
      ))}
    </dl>
  );
}

function RedSection({ stream }: { stream: FunctionStream }) {
  const state = stream.red ?? {};
  const stage = stageOf(stream.red);

  let body: React.ReactNode;
  if (!stream.red) {
    body = <Placeholder text="Awaiting vulnerability analysis." />;
  } else if (state.started && !state.completed && state.vulnerability_found === undefined) {
    body = <Placeholder text="Red Agent is analyzing this function…" />;
  } else if (state.pipeline_status === 'RED_ERROR' || state.red_report?.parse_error) {
    body = (
      <div className="rounded-xl border border-red-500/30 bg-red-950/20 p-3">
        <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-red-200">
          <AlertCircle className="h-4 w-4" /> Red Agent: Response Error
        </div>
        <p className="mb-2 text-xs text-white/60">
          The agent's analysis could not be read. This is an internal failure, not a confirmed
          absence of vulnerabilities.
        </p>
        <CodeBlock
          value={state.red_report?.parse_error || state.error_logs}
          tone="text-red-300"
          maxHeight="max-h-32"
        />
      </div>
    );
  } else if (state.vulnerability_found && !state.exploit_harness) {
    body = (
      <div
        data-testid="red-diagnosis-no-exploit"
        className="rounded-xl border border-amber-500/30 bg-amber-950/10 p-3"
      >
        <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-amber-200">
          <ShieldAlert className="h-4 w-4" /> Defect diagnosed, exploit unavailable
        </div>
        <p className="mb-2 text-xs text-white/60">
          The diagnosis was preserved, but no usable proof of concept could be generated. The
          patch cannot be proven secure without one.
        </p>
        <div className="mb-2 flex flex-wrap gap-1.5 text-[11px]">
          <span className="rounded-full border border-white/15 bg-white/5 px-2 py-0.5 text-white/60">
            exploit: {state.exploit_status || 'UNAVAILABLE'}
          </span>
          {state.exploit_failure_kind && (
            <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 text-amber-200">
              {state.exploit_failure_kind}
            </span>
          )}
        </div>
        <DiagnosisDetails state={state} />
        <CodeBlock value={state.exploit_error} tone="text-amber-200" maxHeight="max-h-32" />
      </div>
    );
  } else if (state.vulnerability_found) {
    body = (
      <div className="rounded-xl border border-red-500/20 bg-red-950/20 p-3">
        <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-red-200">
          <ShieldAlert className="h-4 w-4" /> Red Agent Attack Payload
        </div>
        <DiagnosisDetails state={state} />
        <div className="mb-2 flex flex-wrap gap-1.5 text-[11px]">
          <span className="rounded-full border border-white/15 bg-white/5 px-2 py-0.5 text-white/60">
            harness validation: {state.exploit_status || 'AVAILABLE'}
          </span>
          {state.exploit_type && (
            <span className="rounded-full border border-white/15 bg-white/5 px-2 py-0.5 text-white/60">
              {state.exploit_type}
            </span>
          )}
        </div>
        <CodeBlock value={state.exploit_harness} tone="text-red-200" />
        {state.expected_vulnerable_behavior && (
          <p className="mt-2 text-[11px] text-white/40">
            expected on vulnerable code: {state.expected_vulnerable_behavior}
          </p>
        )}
        <p className="mt-2 text-[11px] text-white/40">
          {stream.terminal ? 'Exploit generated.' : 'Exploit generated — awaiting sandbox validation.'}
        </p>
      </div>
    );
  } else {
    body = (
      <div className="rounded-xl border border-green-500/20 bg-green-950/20 p-3">
        <div className="mb-1 flex items-center gap-2 text-sm font-semibold text-green-200">
          <ShieldAlert className="h-4 w-4" /> Red Agent: No Vulnerability Detected
        </div>
        <p className="text-xs text-white/60">
          The agent analyzed the function and found no exploitable defect.
        </p>
      </div>
    );
  }

  return (
    <SectionShell
      title="Red Agent"
      icon={<ShieldAlert className="h-4 w-4 text-red-300" />}
      accent="border-red-500/15 bg-red-950/10"
      testId="section-red"
      stage={stage}
    >
      {body}
    </SectionShell>
  );
}

function BlueSection({ stream }: { stream: FunctionStream }) {
  const state = stream.blue ?? {};
  const stage = stageOf(stream.blue);

  const downloadPatch = () => {
    const content = state.patch_diff || state.patched_code;
    if (!content) return;
    const url = URL.createObjectURL(new Blob([content], { type: 'text/plain' }));
    const link = document.createElement('a');
    link.href = url;
    link.download = `${stream.functionName || 'vulnguard-fix'}.patch`;
    link.click();
    URL.revokeObjectURL(url);
  };

  let body: React.ReactNode;
  if (!stream.blue) {
    body = <Placeholder text="Awaiting patch generation." />;
  } else if (state.started && !state.completed && !state.patched_code) {
    body = <Placeholder text="Blue Agent is generating the patch…" />;
  } else if (state.pipeline_status === 'BLUE_ERROR' && !state.patched_code) {
    body = (
      <div className="rounded-xl border border-red-500/30 bg-red-950/20 p-3">
        <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-red-200">
          <AlertCircle className="h-4 w-4" /> Blue Agent: Patch Generation Error
        </div>
        <p className="mb-2 text-xs text-white/60">
          The agent could not produce a valid patch response.
        </p>
        <CodeBlock value={state.error_logs} tone="text-red-300" maxHeight="max-h-32" />
      </div>
    );
  } else if (!state.patched_code) {
    body = <Placeholder text="Patch generation has not produced output yet." />;
  } else {
    body = (
      <div className="rounded-xl border border-blue-500/20 bg-blue-950/20 p-3">
        <div className="mb-2 flex items-center gap-2 text-sm font-semibold text-blue-200">
          <Wrench className="h-4 w-4" /> Blue Agent PATCH_GENERATED
        </div>
        <CodeBlock value={state.patch_diff || state.patched_code} tone="text-blue-200" />
        {state.patch_justification && (
          <p className="mt-2 text-xs text-white/60">{state.patch_justification}</p>
        )}
        <p className="mt-2 text-[11px] text-white/40">
          {stream.terminal ? 'Patch generated.' : 'Patch generated — awaiting sandbox validation.'}
        </p>
        {(stream.attemptNumber > 0 || state.error_logs) && (
          <p className="mt-1 text-[11px] text-white/40">
            retry {Math.min(stream.attemptNumber + 1, stream.maxAttempts)}/{stream.maxAttempts}
            {state.error_logs ? ` · ${String(state.error_logs).slice(0, 200)}` : ''}
          </p>
        )}
      </div>
    );
  }

  return (
    <SectionShell
      title="Blue Agent"
      icon={<Wrench className="h-4 w-4 text-blue-300" />}
      accent="border-blue-500/15 bg-blue-950/10"
      testId="section-blue"
      stage={stage}
      actions={
        state.patched_code ? (
          <button
            type="button"
            onClick={downloadPatch}
            className="p-1 text-blue-300 hover:text-white"
            title="Download patch"
            aria-label={`Download patch for ${stream.functionName}`}
          >
            <Download className="h-4 w-4" />
          </button>
        ) : null
      }
    >
      {body}
    </SectionShell>
  );
}

function ExecutionResult({
  label,
  result,
  testId,
}: {
  label: string;
  result?: { ran?: boolean; reproduced?: boolean; success?: boolean; logs?: string };
  testId: string;
}) {
  if (!result) return null;
  const outcome =
    result.ran === false
      ? 'did not run'
      : result.reproduced
        ? 'defect reproduced'
        : result.success === false
          ? 'execution failed'
          : 'defect not reproduced';
  return (
    <div data-testid={testId} className="mb-2 rounded-lg border border-white/10 bg-black/30 p-2">
      <div className="mb-1 flex flex-wrap items-center gap-2 text-[11px]">
        <span className="font-medium text-white/60">{label}</span>
        <span className="rounded-full border border-white/10 bg-white/5 px-2 py-0.5 text-white/50">
          {outcome}
        </span>
      </div>
      <CodeBlock value={result.logs} tone="text-white/60" maxHeight="max-h-40" />
    </div>
  );
}

function JudgeSection({ stream }: { stream: FunctionStream }) {
  const state = stream.judge ?? {};
  const stage = stageOf(stream.judge);
  const isRetry = state.pipeline_status === 'RETRY';
  const attempt = (state.attempt_number ?? 0) + 1;
  const maxAttempts = state.max_attempts ?? stream.maxAttempts ?? 3;

  let body: React.ReactNode;
  if (!stream.judge) {
    body = <Placeholder text="Awaiting patch validation." />;
  } else if (state.started && !state.judge_verdict && !state.original && !state.patched) {
    body = <Placeholder text="Judge Agent is validating the patch in the sandbox…" />;
  } else {
    body = (
      <div
        className={cn(
          'rounded-xl border p-3',
          isRetry ? 'border-orange-500/30 bg-orange-950/10' : 'border-yellow-500/20 bg-yellow-950/10',
        )}
      >
        <div className="mb-2 flex items-center gap-2 text-sm font-semibold">
          {isRetry ? <RefreshCw className="h-4 w-4 text-orange-300" /> : <Scale className="h-4 w-4 text-yellow-300" />}
          <span className={isRetry ? 'text-orange-200' : 'text-yellow-200'}>
            {isRetry ? 'Validation Failed — Retry Scheduled' : 'Judge Agent Verdict'}
          </span>
        </div>
        <p className="mb-3 text-xs text-white/80">
          Verdict:{' '}
          <span className="font-bold text-white">{state.judge_verdict || 'pending'}</span>
          {isRetry && (
            <span className="font-normal text-white/50"> — retry {attempt}/{maxAttempts} in progress</span>
          )}
        </p>

        <dl
          data-testid="judge-verdict-metrics"
          className="mb-2 grid grid-cols-1 gap-1 text-[11px]"
        >
          {[
            ['Sandbox execution', state.build_success === false ? 'failed' : flagText(state.build_success)],
            ['Exploit reproduced', flagText(state.exploit_confirmed)],
            ['Exploit blocked by patch', flagText(state.exploit_blocked)],
            ['Regression tests', flagText(state.test_success)],
            ['Security validated', flagText(state.security_validated)],
            ['Final verdict', state.judge_verdict || 'not reported'],
          ].map(([label, value]) => (
            <div key={label} className="flex gap-2">
              <dt className="w-36 shrink-0 text-white/35">{label}</dt>
              <dd className="text-white/70">{value}</dd>
            </div>
          ))}
        </dl>

        {/* Actual sandbox executions, as they finish. */}
        <ExecutionResult
          label="Original vulnerable source"
          result={state.original}
          testId="judge-original-result"
        />
        <ExecutionResult
          label="Patched source"
          result={state.patched}
          testId="judge-patched-result"
        />
        {(state.build_logs || state.test_logs) && (
          <div className="mb-2 space-y-1 text-[11px] text-white/45">
            {state.build_logs && (
              <p>build: {state.build_success ? 'passed' : 'failed'} · regression:{' '}
                {state.regression_skipped ? 'skipped' : state.test_success ? 'passed' : 'failed'}
              </p>
            )}
            <CodeBlock
              value={[state.build_logs, state.test_logs].filter(Boolean).join('\n')}
              tone="text-white/50"
              maxHeight="max-h-32"
            />
          </div>
        )}

        {state.error_logs && (
          <CodeBlock value={state.error_logs} tone="text-red-300" maxHeight="max-h-40" />
        )}
      </div>
    );
  }

  return (
    <SectionShell
      title="Judge Agent"
      icon={<Scale className="h-4 w-4 text-yellow-300" />}
      accent="border-yellow-500/15 bg-yellow-950/5"
      testId="section-judge"
      stage={stage}
    >
      {body}
    </SectionShell>
  );
}

export function FunctionCard({ stream }: { stream: FunctionStream }) {
  const red = stream.red ?? {};
  const classification = [red.vulnerability_type, red.cwe_id]
    .filter(Boolean)
    .join(' · ');

  return (
    <motion.article
      layout="position"
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      data-testid={`function-card-${stream.key}`}
      className="glassmorphism w-full min-w-0 overflow-hidden rounded-3xl border border-white/10"
    >
      <header className="flex flex-col gap-3 border-b border-white/10 bg-white/5 p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex items-center gap-2 text-sm font-semibold text-white">
              <FileCode className="h-4 w-4 shrink-0 text-white/40" />
              <span className="truncate">{stream.functionName}</span>
            </div>
            <div className="truncate text-[11px] text-white/35">
              {stream.relativePath || '(single file)'} · {stream.functionId}
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span
              data-testid={`stream-status-${stream.key}`}
              className="text-[11px] text-white/40"
            >
              <StatusChip status={stream.status} />
            </span>
            {stream.judgeVerdict && (
              <span
                className={cn(
                  'rounded-full border px-2 py-0.5 text-[11px] font-mono',
                  stream.judgeVerdict === 'PASS'
                    ? 'border-green-500/30 bg-green-500/10 text-green-300'
                    : 'border-white/15 bg-white/5 text-white/60',
                )}
              >
                {stream.judgeVerdict}
              </span>
            )}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-white/45">
          <span className="inline-flex items-center gap-1.5">
            <Cpu className="h-3.5 w-3.5" /> risk{' '}
            {stream.riskScore !== undefined ? `${Math.round(stream.riskScore)}/100` : '—'}
          </span>
          <span>{classification || 'classification pending'}</span>
          {stream.attemptNumber > 0 && (
            <span>
              attempt {Math.min(stream.attemptNumber + 1, stream.maxAttempts)}/{stream.maxAttempts}
            </span>
          )}
          {stream.context && (
            <span className="inline-flex items-center gap-1.5">
              <Network className="h-3.5 w-3.5" />
              {stream.context.imports} imports · {stream.context.callees} callees ·{' '}
              {stream.context.tokenCount} context tokens
            </span>
          )}
        </div>

      </header>

      {/* One vertical sequence per function: ML triage → Red → Blue → Judge.
          Full-width sections keep code, diffs and logs readable; no agent is
          ever rendered as a narrow horizontal column. */}
      <div
        className="flex w-full min-w-0 flex-col gap-4 p-4"
        data-testid={`agent-sections-${stream.key}`}
      >
        <TriageSection stream={stream} />
        <RedSection stream={stream} />
        <BlueSection stream={stream} />
        <JudgeSection stream={stream} />
      </div>

      {stream.errorMessage && (
        <div
          data-testid="pipeline-error"
          className="mx-4 mb-4 rounded-xl border border-red-500/40 bg-red-950/20 p-3"
        >
          <div className="mb-1 flex items-center gap-2">
            <h5 className="text-sm font-bold text-red-300">Agent Pipeline Error</h5>
            <span className="ml-auto rounded-full border border-red-500/30 bg-red-500/10 px-2 py-0.5 text-[11px] text-red-200">
              {stageLabel(stream.failedStage)}
            </span>
          </div>
          {stream.triage && (
            <p className="mb-1 text-[11px] text-white/50">
              ML triage completed and its score above is still valid — this failure happened in a
              later stage, not in triage.
            </p>
          )}
          <code className="block max-w-full whitespace-pre-wrap break-words text-xs text-red-300">
            {stream.errorMessage}
          </code>
        </div>
      )}

      {stream.events.some((event) => event.type === 'status') && (
        <details className="mx-4 mb-4 rounded-xl border border-white/10 bg-black/20 p-3">
          <summary className="cursor-pointer text-[11px] uppercase tracking-wider text-white/40">
            Event log ({stream.events.length})
          </summary>
          <div className="mt-2 space-y-1 font-mono text-[11px] text-white/50">
            {stream.events
              .filter((event) => event.type === 'status')
              .map((event, index) => (
                <div key={`${event.message}-${index}`}>
                  <span className="text-white/25">{'>'}</span> {event.message}
                </div>
              ))}
          </div>
        </details>
      )}

      {stream.terminal && (
        <div className="flex flex-wrap items-center gap-2 border-t border-white/10 px-4 py-2 font-mono text-[11px] text-white/40">
          <span>scan finished:</span>
          <span className="text-white/60">{stream.pipelineStatus}</span>
          {stream.judgeVerdict && <span className="text-white/40">/ {stream.judgeVerdict}</span>}
        </div>
      )}
    </motion.article>
  );
}

export default function AgentFeed({ streams }: { streams: FunctionStream[] }) {
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const [atBottom, setAtBottom] = useState(true);
  const [pendingUpdates, setPendingUpdates] = useState(0);
  const lastSeenCount = useRef(0);
  const totalEvents = streams.reduce((sum, stream) => sum + stream.events.length, 0);

  useEffect(() => {
    if (atBottom) {
      lastSeenCount.current = totalEvents;
      setPendingUpdates(0);
      return;
    }
    const delta = totalEvents - lastSeenCount.current;
    setPendingUpdates(delta > 0 ? delta : 0);
  }, [totalEvents, atBottom]);

  const handleScroll = () => {
    const element = scrollRef.current;
    if (!element) return;
    const nearBottom =
      element.scrollHeight - element.scrollTop - element.clientHeight < 32;
    setAtBottom(nearBottom);
    if (nearBottom) {
      lastSeenCount.current = totalEvents;
      setPendingUpdates(0);
    }
  };

  const scrollToLatest = () => {
    const element = scrollRef.current;
    if (!element) return;
    // Only on an explicit user action — new events never move the viewport.
    element.scrollTop = element.scrollHeight;
    lastSeenCount.current = totalEvents;
    setPendingUpdates(0);
    setAtBottom(true);
  };

  if (streams.length === 0) {
    return (
      <div className="flex h-full items-center justify-center text-white/30">
        <div className="flex flex-col items-center gap-4">
          <Terminal className="h-12 w-12" />
          <p>Select a function or scan all to begin analysis</p>
        </div>
      </div>
    );
  }

  return (
    <div className="relative h-full">
      <div
        ref={scrollRef}
        onScroll={handleScroll}
        className="h-full space-y-5 overflow-y-auto p-5"
        data-testid="live-stream-scroll"
      >
        <div className="flex items-center gap-2 text-[11px] uppercase tracking-wider text-white/35">
          <PlayCircle className="h-3.5 w-3.5" />
          {streams.length} function{streams.length === 1 ? '' : 's'} in this scan
        </div>
        <AnimatePresence initial={false}>
          {streams.map((stream) => (
            <FunctionCard key={stream.key} stream={stream} />
          ))}
        </AnimatePresence>
      </div>

      {pendingUpdates > 0 && !atBottom && (
        <button
          type="button"
          onClick={scrollToLatest}
          className="absolute bottom-4 left-1/2 z-10 flex -translate-x-1/2 items-center gap-2 rounded-full border border-white/20 bg-black/80 px-3 py-1.5 text-xs text-white/80 shadow-xl backdrop-blur hover:bg-black"
        >
          <ArrowDown className="h-3.5 w-3.5" />
          {pendingUpdates} new update{pendingUpdates === 1 ? '' : 's'}
        </button>
      )}
    </div>
  );
}
