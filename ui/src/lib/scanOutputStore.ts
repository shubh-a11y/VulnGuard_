// Browser-local memory for completed scan output.
//
// The live agent stream lives in React state, so it disappears on reload and
// when a new scan starts. Completed streams are kept in localStorage so the
// user can reopen them later, and can delete individual runs or everything.

export interface StoredScanOutput {
  id: string;
  functionId: string;
  functionName: string;
  relativePath: string;
  startedAt: string;
  finishedAt: string;
  pipelineStatus?: string;
  judgeVerdict?: string;
  events: any[];
}

const STORAGE_KEY = 'vulnguard.scan_outputs.v1';

export const MAX_STORED_OUTPUTS = 20;

// Older runs are dropped before this budget is exceeded; localStorage is
// commonly limited to ~5 MB per origin.
const MAX_STORAGE_BYTES = 2_000_000;

function storage(): Storage | null {
  try {
    return typeof window === 'undefined' ? null : window.localStorage;
  } catch {
    return null;
  }
}

function isStoredScanOutput(value: unknown): value is StoredScanOutput {
  if (!value || typeof value !== 'object') return false;
  const run = value as Partial<StoredScanOutput>;
  return (
    typeof run.id === 'string' &&
    typeof run.functionName === 'string' &&
    Array.isArray(run.events)
  );
}

export function loadStoredOutputs(): StoredScanOutput[] {
  const store = storage();
  if (!store) return [];
  try {
    const parsed = JSON.parse(store.getItem(STORAGE_KEY) ?? '[]');
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(isStoredScanOutput).slice(0, MAX_STORED_OUTPUTS);
  } catch {
    // Corrupt or hand-edited storage must never break the dashboard.
    return [];
  }
}

function persist(runs: StoredScanOutput[]): void {
  const store = storage();
  if (!store) return;
  let kept = runs.slice(0, MAX_STORED_OUTPUTS);
  try {
    while (kept.length > 1 && JSON.stringify(kept).length > MAX_STORAGE_BYTES) {
      kept = kept.slice(0, -1);
    }
    store.setItem(STORAGE_KEY, JSON.stringify(kept));
  } catch (err) {
    // Quota errors and disabled storage (private mode) must not fail a scan.
    console.warn('Could not persist scan output locally', err);
  }
}

export function saveStoredOutput(run: StoredScanOutput): StoredScanOutput[] {
  persist([run, ...loadStoredOutputs().filter((item) => item.id !== run.id)]);
  return loadStoredOutputs();
}

export function deleteStoredOutput(id: string): StoredScanOutput[] {
  persist(loadStoredOutputs().filter((item) => item.id !== id));
  return loadStoredOutputs();
}

export function clearStoredOutputs(): void {
  const store = storage();
  if (!store) return;
  try {
    store.removeItem(STORAGE_KEY);
  } catch (err) {
    console.warn('Could not clear stored scan output', err);
  }
}
