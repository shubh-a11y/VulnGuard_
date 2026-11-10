import { describe, expect, it } from 'vitest';
import {
  applyEventToStreams,
  applyStreamEvent,
  createStream,
  finalStatus,
  streamFromStoredOutput,
  streamKey,
  upsertStream,
  type FunctionStream,
} from './functionStreams';
import type { StoredScanOutput } from './scanOutputStore';

const makeStream = (name: string, scanId = 'scan-1', relativePath = 'vuln.py'): FunctionStream =>
  createStream({
    scanId,
    functionId: `${relativePath}:${name}`,
    functionName: name,
    relativePath,
    startedAt: '2026-11-06T10:00:00.000Z',
  });

const redUpdate = (name: string, state: Record<string, unknown>, scanId = 'scan-1') => ({
  type: 'agent_update',
  agent: 'red_agent',
  scan_id: scanId,
  function_id: `vuln.py:${name}`,
  state,
});

const judgeUpdate = (state: Record<string, unknown>) => ({
  type: 'agent_update',
  agent: 'judge_agent',
  state,
});

describe('functionStreams', () => {
  it('builds a stable key from the scan and the function', () => {
    expect(streamKey('scan-1', 'vuln.py:ping_host')).toBe('scan-1::vuln.py:ping_host');
    expect(makeStream('ping_host').key).toBe('scan-1::vuln.py:ping_host');
  });

  it('applies an event to exactly one function', () => {
    const first = makeStream('first');
    const second = makeStream('second');
    const streams = applyEventToStreams(
      [first, second],
      second.key,
      redUpdate('second', { vulnerability_found: true, exploit_harness: 'payload' }),
    );

    expect(streams).toHaveLength(2);
    // The untouched stream keeps its identity, so React does not re-render it.
    expect(streams[0]).toBe(first);
    expect(streams[1]).not.toBe(second);
    expect(streams[1].red?.exploit_harness).toBe('payload');
    expect(streams[0].red).toBeNull();
  });

  it('ignores a duplicated event instead of repeating the history', () => {
    const stream = makeStream('ping_host');
    const event = redUpdate('ping_host', { vulnerability_found: false });
    const once = applyStreamEvent(stream, event);
    const twice = applyStreamEvent(once, { ...event });

    expect(once.events).toHaveLength(1);
    expect(twice.events).toHaveLength(1);
  });

  it('keeps five concurrent functions and never reorders them', () => {
    const names = ['a', 'b', 'c', 'd', 'e'];
    let streams = names.map((name) => makeStream(name));
    const order = streams.map((stream) => stream.key);

    streams = applyEventToStreams(streams, streams[2].key, redUpdate('c', {
      vulnerability_found: true,
      exploit_harness: 'print(1)',
    }));
    streams = applyEventToStreams(streams, streams[4].key, judgeUpdate({
      pipeline_status: 'COMPLETE',
      judge_verdict: 'PASS',
    }));

    expect(streams.map((stream) => stream.key)).toEqual(order);
    expect(streams[2].red?.exploit_harness).toBe('print(1)');
    expect(streams[4].status).toBe('PASS');
    expect(streams.filter((stream) => stream.status === 'QUEUED')).toHaveLength(3);
  });

  it('upserts without creating duplicate cards', () => {
    const stream = makeStream('ping_host');
    const next = upsertStream(upsertStream([], stream), { ...stream, status: 'RUNNING' });

    expect(next).toHaveLength(1);
    expect(next[0].status).toBe('RUNNING');
  });

  it('tracks retry progress and the terminal verdict', () => {
    let stream = makeStream('ping_host');
    stream = applyStreamEvent(stream, judgeUpdate({
      pipeline_status: 'RETRY',
      judge_verdict: 'EXPLOIT_NOT_BLOCKED',
      attempt_number: 1,
      max_attempts: 3,
    }));

    expect(stream.status).toBe('RETRYING');
    expect(stream.attemptNumber).toBe(1);

    stream = applyStreamEvent(stream, {
      type: 'complete',
      pipeline_status: 'COMPLETE',
      judge_verdict: 'PASS',
      security_validated: true,
    });

    expect(stream.status).toBe('PASS');
    expect(stream.terminal).toBe(true);
    expect(stream.securityValidated).toBe(true);
  });

  it('reports inconclusive evidence as inconclusive, never as a pass', () => {
    expect(finalStatus('COMPLETE', 'PASS')).toBe('PASS');
    expect(finalStatus('COMPLETE', 'SANDBOX_UNAVAILABLE')).toBe('INCONCLUSIVE');
    expect(finalStatus('FAILED', 'EXPLOIT_GENERATION_FAILED')).toBe('INCONCLUSIVE');
    expect(finalStatus('FAILED', 'HARNESS_INVALID')).toBe('INCONCLUSIVE');
    expect(finalStatus('FAILED', 'BUILD_FAILED')).toBe('FAIL');
    expect(finalStatus('FAILED', 'RED_AGENT_ERROR')).toBe('INCONCLUSIVE');
    expect(finalStatus('COMPLETE', undefined)).toBe('COMPLETED');
  });

  it('rebuilds independent Red, Blue and Judge sections from stored events', () => {
    const run: StoredScanOutput = {
      id: 'stored-run',
      functionId: 'vuln_cmdi.py:ping_host',
      functionName: 'ping_host',
      relativePath: 'vuln_cmdi.py',
      startedAt: '2026-11-06T10:00:00.000Z',
      finishedAt: '2026-11-06T10:01:00.000Z',
      pipelineStatus: 'FAILED',
      judgeVerdict: 'EXPLOIT_NOT_BLOCKED',
      events: [
        { type: 'status', message: 'Starting scan...' },
        { type: 'triage_result', score: 91.2, threshold: 65, is_high_risk: true },
        { type: 'context_result', imports: 2, callees: 1, token_count: 40 },
        redUpdate('ping_host', {
          vulnerability_found: true,
          vulnerability_type: 'COMMAND_INJECTION',
          exploit_harness: 'os.system(cmd)',
          exploit_status: 'AVAILABLE',
        }),
        { type: 'agent_update', agent: 'blue_agent', state: { patched_code: 'safe()' } },
        judgeUpdate({ pipeline_status: 'FAILED', judge_verdict: 'EXPLOIT_NOT_BLOCKED' }),
      ],
    };

    const stream = streamFromStoredOutput(run);

    expect(stream.source).toBe('stored');
    expect(stream.red?.vulnerability_type).toBe('COMMAND_INJECTION');
    expect(stream.blue?.patched_code).toBe('safe()');
    expect(stream.judge?.judge_verdict).toBe('EXPLOIT_NOT_BLOCKED');
    expect(stream.triage?.score).toBe(91.2);
    expect(stream.context?.imports).toBe(2);
    expect(stream.terminal).toBe(true);
    expect(stream.status).toBe('FAIL');
  });
});
