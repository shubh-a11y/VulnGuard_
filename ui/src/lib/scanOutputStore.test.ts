import { beforeEach, describe, expect, it } from 'vitest';
import {
  MAX_STORED_OUTPUTS,
  clearStoredOutputs,
  deleteStoredOutput,
  loadStoredOutputs,
  saveStoredOutput,
} from './scanOutputStore';

const makeRun = (id: string) => ({
  id,
  functionId: `sample.py:fn_${id}`,
  functionName: `fn_${id}`,
  relativePath: 'sample.py',
  startedAt: '2026-01-01T00:00:00.000Z',
  finishedAt: '2026-01-01T00:01:00.000Z',
  pipelineStatus: 'FAILED',
  judgeVerdict: 'EXPLOIT_INVALID',
  events: [{ type: 'complete', pipeline_status: 'FAILED' }],
});

describe('scanOutputStore', () => {
  beforeEach(() => {
    clearStoredOutputs();
  });

  it('keeps the newest run first and replaces an existing id', () => {
    saveStoredOutput(makeRun('first'));
    saveStoredOutput({ ...makeRun('first'), judgeVerdict: 'PASS' });
    saveStoredOutput(makeRun('second'));

    const runs = loadStoredOutputs();
    expect(runs.map((run) => run.id)).toEqual(['second', 'first']);
    expect(runs[1].judgeVerdict).toBe('PASS');
  });

  it('caps the number of stored runs', () => {
    for (let index = 0; index < MAX_STORED_OUTPUTS + 5; index += 1) {
      saveStoredOutput(makeRun(`run-${index}`));
    }

    const runs = loadStoredOutputs();
    expect(runs).toHaveLength(MAX_STORED_OUTPUTS);
    expect(runs[0].id).toBe(`run-${MAX_STORED_OUTPUTS + 4}`);
  });

  it('deletes a single run and clears everything', () => {
    saveStoredOutput(makeRun('keep'));
    saveStoredOutput(makeRun('drop'));

    expect(deleteStoredOutput('drop').map((run) => run.id)).toEqual(['keep']);

    clearStoredOutputs();
    expect(loadStoredOutputs()).toEqual([]);
  });

  it('ignores corrupt or malformed stored data', () => {
    window.localStorage.setItem('vulnguard.scan_outputs.v1', '{not json');
    expect(loadStoredOutputs()).toEqual([]);

    window.localStorage.setItem(
      'vulnguard.scan_outputs.v1',
      JSON.stringify([{ id: 'no-events' }, makeRun('valid')]),
    );
    expect(loadStoredOutputs().map((run) => run.id)).toEqual(['valid']);
  });
});
