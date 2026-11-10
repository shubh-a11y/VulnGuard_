// Per-function execution state for the Agent Live Stream.
//
// The live stream used to be a single flat `events` array, so starting another
// function replaced everything the user was reading. Every function now owns an
// independent, keyed record (`scanId + functionId`) and socket events are
// applied to exactly one record.

import type { StoredScanOutput } from './scanOutputStore';

export type StreamStatus =
  | 'QUEUED'
  | 'RUNNING'
  | 'RETRYING'
  | 'COMPLETED'
  | 'PASS'
  | 'FAIL'
  | 'INCONCLUSIVE';

export interface TriageFeature {
  name: string;
  value: number;
}

export interface TriageInfo {
  score: number;
  threshold?: number;
  isHighRisk: boolean;
  /** Extracted features that contributed to the score, largest first. */
  features: TriageFeature[];
  /** High-confidence static signal that bypassed the probabilistic model. */
  staticSignal?: string;
}

export interface ContextInfo {
  imports: number;
  callees: number;
  tokenCount: number;
}

export interface FunctionStream {
  /** Stable identity: `scanId::functionId`. */
  key: string;
  scanId: string;
  functionId: string;
  functionName: string;
  relativePath: string;
  status: StreamStatus;
  pipelineStatus: string;
  judgeVerdict: string;
  riskScore?: number;
  isHighRisk?: boolean;
  triage?: TriageInfo;
  context?: ContextInfo;
  red: Record<string, any> | null;
  blue: Record<string, any> | null;
  judge: Record<string, any> | null;
  attemptNumber: number;
  maxAttempts: number;
  exploitStatus?: string;
  exploitFailureKind?: string;
  securityValidated?: boolean;
  errorMessage?: string;
  failedStage?: string;
  terminal: boolean;
  startedAt: string;
  updatedAt: string;
  events: any[];
  source: 'live' | 'stored';
}

// A verdict that settles the evidence without proving the patch: the run is
// neither a success nor evidence that the vulnerability is absent.
export const INCONCLUSIVE_VERDICTS = new Set([
  'SANDBOX_UNAVAILABLE',
  'EXPLOIT_GENERATION_FAILED',
  'HARNESS_INVALID',
  'EXPLOIT_UNAVAILABLE',
  'EXPLOIT_INVALID',
  'EXPLOIT_NOT_REPRODUCED',
  'EXPLOIT_EXECUTION_ERROR',
  'PIPELINE_INCOMPLETE',
  'RED_AGENT_ERROR',
]);

export const FAIL_VERDICTS = new Set([
  'BUILD_FAILED',
  'TESTS_FAILED',
  'EXPLOIT_NOT_BLOCKED',
  'DESTRUCTIVE_PATCH_REJECTED',
  'NEW_VULNERABILITY_INTRODUCED',
  'NEW_DEPENDENCIES_REJECTED',
  'PATCH_GENERATION_FAILED',
  'INTERFACE_VIOLATION',
  'MAX_RETRIES_EXHAUSTED',
]);

export const streamKey = (scanId: string, functionId: string) => `${scanId}::${functionId}`;

export function finalStatus(
  pipelineStatus?: string,
  judgeVerdict?: string,
): StreamStatus {
  if (judgeVerdict === 'PASS') return 'PASS';
  if (judgeVerdict && INCONCLUSIVE_VERDICTS.has(judgeVerdict)) return 'INCONCLUSIVE';
  if (judgeVerdict && FAIL_VERDICTS.has(judgeVerdict)) return 'FAIL';

  switch (pipelineStatus) {
    case 'COMPLETE':
    case 'COMPLETED':
      return judgeVerdict ? 'FAIL' : 'COMPLETED';
    case 'FAILED':
    case 'ERROR':
    case 'DISCONNECTED':
      return 'FAIL';
    case 'CANCELLED':
      return 'INCONCLUSIVE';
    case 'RETRY':
      return 'RETRYING';
    default:
      return pipelineStatus ? 'RUNNING' : 'QUEUED';
  }
}

export function createStream(params: {
  scanId: string;
  functionId: string;
  functionName: string;
  relativePath?: string;
  startedAt?: string;
  source?: 'live' | 'stored';
}): FunctionStream {
  const startedAt = params.startedAt ?? new Date().toISOString();
  return {
    key: streamKey(params.scanId, params.functionId),
    scanId: params.scanId,
    functionId: params.functionId,
    functionName: params.functionName,
    relativePath: params.relativePath ?? '',
    status: 'QUEUED',
    pipelineStatus: 'QUEUED',
    judgeVerdict: '',
    red: null,
    blue: null,
    judge: null,
    attemptNumber: 0,
    maxAttempts: 3,
    terminal: false,
    startedAt,
    updatedAt: startedAt,
    events: [],
    source: params.source ?? 'live',
  };
}

export function applyStreamEvent(
  stream: FunctionStream,
  event: any,
  at: string = new Date().toISOString(),
): FunctionStream {
  if (!event || typeof event !== 'object') return stream;

  const last = stream.events[stream.events.length - 1];
  if (last) {
    // A replayed or duplicated socket event must not double the card's history
    // or restart a finished section.
    try {
      if (JSON.stringify(last) === JSON.stringify(event)) return stream;
    } catch {
      // Unserializable payloads are applied normally.
    }
  }

  const next: FunctionStream = {
    ...stream,
    // Cap the raw log so a very long retry history cannot grow unbounded.
    events: [...stream.events, event].slice(-1000),
    updatedAt: at,
  };

  switch (event.type) {
    case 'status':
      if (!next.terminal) {
        next.status = 'RUNNING';
        next.pipelineStatus = 'RUNNING';
      }
      break;

    case 'triage_result': {
      const features = Object.entries(
        (event.features ?? {}) as Record<string, unknown>,
      )
        .map(([name, value]) => ({ name, value: Number(value) }))
        .filter((feature) => Number.isFinite(feature.value) && feature.value !== 0)
        .sort((a, b) => b.value - a.value)
        .slice(0, 12);
      next.triage = {
        score: Number(event.score ?? 0),
        threshold: typeof event.threshold === 'number' ? event.threshold : undefined,
        isHighRisk: Boolean(event.is_high_risk),
        features,
        staticSignal:
          typeof event.static_signal === 'string' && event.static_signal
            ? event.static_signal
            : undefined,
      };
      next.riskScore = Number(event.score ?? next.riskScore ?? 0);
      next.isHighRisk = Boolean(event.is_high_risk);
      if (!next.terminal) {
        next.status = 'RUNNING';
        next.pipelineStatus = 'TRIAGE';
      }
      break;
    }

    case 'context_result':
      next.context = {
        imports: Number(event.imports ?? 0),
        callees: Number(event.callees ?? 0),
        tokenCount: Number(event.token_count ?? 0),
      };
      break;

    case 'agent_update': {
      const state = event.state ?? {};
      if (event.agent === 'red_agent') {
        // Merge, don't replace: the progressive diagnosis/harness events already
        // rendered on the card must survive the node's final state update.
        next.red = { ...(next.red ?? {}), ...state, started: true, completed: true };
        next.exploitStatus = state.exploit_status ?? next.exploitStatus;
        next.exploitFailureKind = state.exploit_failure_kind || next.exploitFailureKind;
      } else if (event.agent === 'blue_agent') {
        next.blue = { ...(next.blue ?? {}), ...state, started: true, completed: true };
      } else if (event.agent === 'judge_agent') {
        next.judge = { ...(next.judge ?? {}), ...state, started: true, completed: true };
        next.attemptNumber = Number(state.attempt_number ?? next.attemptNumber);
        next.maxAttempts = Number(state.max_attempts ?? next.maxAttempts);
        next.judgeVerdict = state.judge_verdict || next.judgeVerdict;
      }
      next.pipelineStatus = state.pipeline_status || next.pipelineStatus;
      if (!next.terminal) {
        if (state.pipeline_status === 'RETRY') {
          next.status = 'RETRYING';
        } else if (
          state.pipeline_status === 'COMPLETE' ||
          state.pipeline_status === 'COMPLETED' ||
          state.pipeline_status === 'FAILED' ||
          state.pipeline_status === 'ERROR'
        ) {
          // The Judge's terminal update already carries the verdict; show it now
          // instead of waiting for the final `complete` event.
          next.status = finalStatus(next.pipelineStatus, next.judgeVerdict);
        } else {
          next.status = 'RUNNING';
        }
      }
      break;
    }

    // ── Progressive agent events ──────────────────────────────────────
    // Emitted by the nodes while they execute, so each section fills in as
    // real results arrive instead of waiting for the whole node to finish.
    case 'red_started':
      next.red = { ...(next.red ?? {}), started: true, completed: false };
      if (!next.terminal) {
        next.status = 'RUNNING';
        next.pipelineStatus = 'RED';
      }
      break;

    case 'red_diagnosis':
      next.red = {
        ...(next.red ?? {}),
        ...(event.diagnosis ?? {}),
        started: true,
        vulnerability_found: Boolean(event.vulnerability_found),
      };
      break;

    case 'red_harness_generated':
      next.red = {
        ...(next.red ?? {}),
        started: true,
        vulnerability_found: true,
        exploit_type: event.exploit_type ?? null,
        exploit_harness: event.exploit_code_harness ?? null,
        expected_stdout_regex: event.expected_stdout_regex ?? null,
        exploit_status: event.exploit_status,
        exploit_failure_kind: event.exploit_failure_kind ?? '',
        exploit_error: event.exploit_error ?? null,
      };
      next.exploitStatus = event.exploit_status ?? next.exploitStatus;
      next.exploitFailureKind = event.exploit_failure_kind || next.exploitFailureKind;
      break;

    case 'red_completed':
      next.red = {
        ...(next.red ?? {}),
        ...(event.diagnosis ?? {}),
        started: true,
        completed: true,
        vulnerability_found: Boolean(event.vulnerability_found),
        exploit_status: event.exploit_status ?? next.red?.exploit_status,
        exploit_failure_kind: event.exploit_failure_kind ?? next.red?.exploit_failure_kind,
        exploit_error: event.exploit_error ?? next.red?.exploit_error,
      };
      next.exploitStatus = event.exploit_status ?? next.exploitStatus;
      next.exploitFailureKind = event.exploit_failure_kind || next.exploitFailureKind;
      next.pipelineStatus = event.pipeline_status || 'RED_COMPLETE';
      if (!next.terminal) next.status = 'RUNNING';
      break;

    case 'blue_started':
      next.blue = {
        ...(next.blue ?? {}),
        started: true,
        completed: false,
        attempt_number: Number(event.attempt_number ?? next.blue?.attempt_number ?? 0),
      };
      if (!next.terminal) {
        next.status = 'RUNNING';
        next.pipelineStatus = 'BLUE';
      }
      break;

    case 'blue_patch_generated':
      next.blue = {
        ...(next.blue ?? {}),
        started: true,
        patched_code: event.patched_code ?? null,
        patch_diff: event.patch_diff ?? null,
        patch_justification: event.patch_justification ?? null,
        changes_summary: event.changes_summary ?? next.blue?.changes_summary,
        pipeline_status: 'BLUE_COMPLETE',
      };
      break;

    case 'blue_completed':
      next.blue = {
        ...(next.blue ?? {}),
        started: true,
        completed: true,
        pipeline_status: event.pipeline_status ?? next.blue?.pipeline_status,
        patched_code: event.patched_code ?? next.blue?.patched_code ?? null,
        patch_diff: event.patch_diff ?? next.blue?.patch_diff ?? null,
        patch_justification:
          event.patch_justification ?? next.blue?.patch_justification ?? null,
        error_logs: event.error_logs ?? next.blue?.error_logs ?? '',
      };
      next.pipelineStatus = event.pipeline_status || next.pipelineStatus;
      break;

    case 'judge_started':
      next.judge = {
        ...(next.judge ?? {}),
        started: true,
        completed: false,
        attempt_number: Number(event.attempt_number ?? next.judge?.attempt_number ?? 0),
        max_attempts: Number(event.max_attempts ?? next.judge?.max_attempts ?? next.maxAttempts),
      };
      if (!next.terminal) {
        next.status = 'RUNNING';
        next.pipelineStatus = 'JUDGE';
      }
      break;

    case 'judge_build_result':
      next.judge = {
        ...(next.judge ?? {}),
        started: true,
        build_success: Boolean(event.success),
        build_logs: event.logs ?? '',
      };
      break;

    case 'judge_regression_result':
      next.judge = {
        ...(next.judge ?? {}),
        started: true,
        test_success: Boolean(event.success),
        test_logs: event.logs ?? '',
        regression_skipped: Boolean(event.skipped),
      };
      break;

    case 'judge_original_result':
      next.judge = {
        ...(next.judge ?? {}),
        started: true,
        exploit_confirmed: Boolean(event.reproduced),
        original: {
          ran: Boolean(event.ran),
          reproduced: Boolean(event.reproduced),
          success: Boolean(event.success),
          logs: event.logs ?? '',
        },
      };
      break;

    case 'judge_patched_result':
      next.judge = {
        ...(next.judge ?? {}),
        started: true,
        // The exploit is blocked only when the patched run actually executed
        // and did not reproduce the defect.
        exploit_blocked: Boolean(event.ran) && !event.reproduced,
        patched: {
          ran: Boolean(event.ran),
          reproduced: Boolean(event.reproduced),
          success: Boolean(event.success),
          logs: event.logs ?? '',
        },
      };
      break;

    case 'judge_completed':
      next.judge = {
        ...(next.judge ?? {}),
        started: true,
        completed: true,
        judge_verdict: event.judge_verdict,
        pipeline_status: event.pipeline_status,
        build_success: Boolean(event.build_success),
        test_success: Boolean(event.test_success),
        exploit_confirmed: Boolean(event.exploit_confirmed),
        exploit_blocked: Boolean(event.exploit_blocked),
        security_validated: Boolean(event.security_validated),
        error_logs: event.error_logs ?? '',
        attempt_number: Number(event.attempt_number ?? next.judge?.attempt_number ?? 0),
        max_attempts: Number(event.max_attempts ?? next.judge?.max_attempts ?? next.maxAttempts),
      };
      next.judgeVerdict = event.judge_verdict || next.judgeVerdict;
      next.attemptNumber = Number(event.attempt_number ?? next.attemptNumber);
      next.pipelineStatus = event.pipeline_status || next.pipelineStatus;
      if (!next.terminal) {
        next.status =
          next.pipelineStatus === 'RETRY'
            ? 'RETRYING'
            : finalStatus(next.pipelineStatus, next.judgeVerdict);
      }
      break;

    case 'complete':
      next.pipelineStatus = event.pipeline_status || next.pipelineStatus;
      next.judgeVerdict = event.judge_verdict || next.judgeVerdict;
      next.exploitStatus = event.exploit_status ?? next.exploitStatus;
      if (event.security_validated !== undefined) {
        next.securityValidated = Boolean(event.security_validated);
      }
      next.status = finalStatus(next.pipelineStatus, next.judgeVerdict);
      next.terminal = true;
      break;

    case 'error':
      next.errorMessage = event.message || 'Unknown pipeline error';
      next.failedStage = event.stage;
      next.status = 'FAIL';
      next.terminal = true;
      break;

    default:
      break;
  }

  return next;
}

/** Apply one event to exactly one stream; every other stream is untouched. */
export function applyEventToStreams(
  streams: FunctionStream[],
  key: string,
  event: any,
  at?: string,
): FunctionStream[] {
  let changed = false;
  const next = streams.map((stream) => {
    if (stream.key !== key) return stream;
    changed = true;
    return applyStreamEvent(stream, event, at);
  });
  return changed ? next : streams;
}

/** Insert or replace a stream in place, so cards do not jump while scanning. */
export function upsertStream(
  streams: FunctionStream[],
  stream: FunctionStream,
): FunctionStream[] {
  const index = streams.findIndex((item) => item.key === stream.key);
  if (index === -1) return [...streams, stream];
  const next = streams.slice();
  next[index] = stream;
  return next;
}

/**
 * Rebuild a stream from a stored run so a reloaded stream renders exactly like
 * the live one (same Red/Blue/Judge sections, same final status).
 */
export function streamFromStoredOutput(run: StoredScanOutput): FunctionStream {
  const stream = createStream({
    scanId: `stored-${run.id}`,
    functionId: run.functionId || run.functionName,
    functionName: run.functionName,
    relativePath: run.relativePath,
    startedAt: run.startedAt,
    source: 'stored',
  });
  const replayed = run.events.reduce<FunctionStream>(
    (acc, event) => applyStreamEvent(acc, event, run.finishedAt || acc.updatedAt),
    stream,
  );
  if (!replayed.terminal) {
    const pipelineStatus = run.pipelineStatus ?? replayed.pipelineStatus;
    const judgeVerdict = run.judgeVerdict ?? replayed.judgeVerdict;
    return {
      ...replayed,
      pipelineStatus,
      judgeVerdict,
      status: finalStatus(pipelineStatus, judgeVerdict),
      terminal: true,
    };
  }
  return replayed;
}

export function streamToStoredOutput(stream: FunctionStream): StoredScanOutput {
  return {
    id: stream.key,
    functionId: stream.functionId,
    functionName: stream.functionName,
    relativePath: stream.relativePath,
    startedAt: stream.startedAt,
    finishedAt: stream.updatedAt,
    pipelineStatus: stream.pipelineStatus,
    judgeVerdict: stream.judgeVerdict,
    events: stream.events,
  };
}
