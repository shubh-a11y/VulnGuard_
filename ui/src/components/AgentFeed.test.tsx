import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import AgentFeed from './AgentFeed';
import { applyStreamEvent, createStream, type FunctionStream } from '../lib/functionStreams';

const startedAt = '2026-11-06T10:00:00.000Z';

const statusEvent = (message: string) => ({ type: 'status', message });

const redUpdate = (state: Record<string, unknown>) => ({
  type: 'agent_update',
  agent: 'red_agent',
  state,
});

const blueUpdate = (state: Record<string, unknown>) => ({
  type: 'agent_update',
  agent: 'blue_agent',
  state,
});

const judgeUpdate = (state: Record<string, unknown>) => ({
  type: 'agent_update',
  agent: 'judge_agent',
  state,
});

function streamFor(name: string, events: any[] = [], relativePath = 'vuln.py'): FunctionStream {
  const stream = createStream({
    scanId: 'scan-1',
    functionId: `${relativePath}:${name}`,
    functionName: name,
    relativePath,
    startedAt,
  });
  return events.reduce(
    (acc, event) => applyStreamEvent(acc, event, startedAt),
    stream,
  );
}

const card = (stream: FunctionStream) => screen.getByTestId(`function-card-${stream.key}`);

describe('AgentFeed multi-function stream', () => {
  let scrollIntoViewSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    scrollIntoViewSpy = vi.fn();
    Element.prototype.scrollIntoView = scrollIntoViewSpy as unknown as typeof Element.prototype.scrollIntoView;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders one card per flagged function and keeps all five visible', () => {
    const streams = ['first', 'second', 'third', 'fourth', 'fifth'].map((name) =>
      streamFor(name, [statusEvent(`Starting scan for ${name}...`)]),
    );

    render(<AgentFeed streams={streams} />);

    expect(screen.getAllByTestId(/^function-card-/)).toHaveLength(5);
    for (const name of ['first', 'second', 'third', 'fourth', 'fifth']) {
      expect(screen.getByText(name)).toBeInTheDocument();
    }
    expect(screen.getByText(/5 functions in this scan/)).toBeInTheDocument();
  });

  it('keeps each function’s Red, Blue and Judge sections independent', () => {
    const first = streamFor('ping_host', [
      redUpdate({
        pipeline_status: 'RED_COMPLETE',
        vulnerability_found: true,
        vulnerability_type: 'COMMAND_INJECTION',
        exploit_code_harness: 'print("FIRST_FUNCTION_PAYLOAD")',
        exploit_harness: 'print("FIRST_FUNCTION_PAYLOAD")',
        exploit_status: 'AVAILABLE',
      }),
      blueUpdate({ pipeline_status: 'BLUE_COMPLETE', patched_code: 'FIRST_FUNCTION_PATCH' }),
    ]);
    const second = streamFor('process_data', [
      redUpdate({
        pipeline_status: 'RED_COMPLETE',
        vulnerability_found: true,
        vulnerability_type: 'BUFFER_OVERFLOW',
        exploit_code_harness: 'print("SECOND_FUNCTION_PAYLOAD")',
        exploit_harness: 'print("SECOND_FUNCTION_PAYLOAD")',
        exploit_status: 'AVAILABLE',
      }),
    ]);

    render(<AgentFeed streams={[first, second]} />);

    const firstCard = card(first);
    const secondCard = card(second);

    expect(within(firstCard).getByText(/FIRST_FUNCTION_PAYLOAD/)).toBeInTheDocument();
    expect(within(firstCard).getByText(/FIRST_FUNCTION_PATCH/)).toBeInTheDocument();
    expect(within(firstCard).queryByText(/SECOND_FUNCTION_PAYLOAD/)).not.toBeInTheDocument();

    expect(within(secondCard).getByText(/SECOND_FUNCTION_PAYLOAD/)).toBeInTheDocument();
    expect(within(secondCard).getByText(/Awaiting patch generation/)).toBeInTheDocument();
    expect(within(secondCard).queryByText(/FIRST_FUNCTION_PAYLOAD/)).not.toBeInTheDocument();
  });

  it('does not auto-scroll when new stream events arrive', () => {
    const { rerender } = render(<AgentFeed streams={[streamFor('ping_host', [statusEvent('Starting scan...')])]} />);
    expect(scrollIntoViewSpy).not.toHaveBeenCalled();

    rerender(
      <AgentFeed
        streams={[
          streamFor('ping_host', [
            statusEvent('Starting scan...'),
            redUpdate({ pipeline_status: 'RED_COMPLETE', vulnerability_found: false }),
            judgeUpdate({ pipeline_status: 'COMPLETE', judge_verdict: 'PASS' }),
          ]),
        ]}
      />,
    );

    expect(scrollIntoViewSpy).not.toHaveBeenCalled();
  });

  it('does not change the window scroll position on new events', () => {
    const scrollToSpy = vi.fn();
    window.scrollTo = scrollToSpy as unknown as typeof window.scrollTo;

    const { rerender } = render(<AgentFeed streams={[streamFor('ping_host')]} />);
    rerender(
      <AgentFeed
        streams={Array.from({ length: 20 }, (_, index) =>
          streamFor(`function_${index}`, [statusEvent(`event ${index}`)]),
        )}
      />,
    );

    expect(scrollToSpy).not.toHaveBeenCalled();
    expect(scrollIntoViewSpy).not.toHaveBeenCalled();
  });

  it('renders a Red Agent response error as an error, not as a detection result', () => {
    render(
      <AgentFeed
        streams={[
          streamFor('ping_host', [
            redUpdate({
              pipeline_status: 'RED_ERROR',
              vulnerability_found: false,
              red_report: {
                parse_error: 'schema validation: Unterminated string at line 4',
                raw: '{"vulnerability_found": true, "cwe',
              },
            }),
          ]),
        ]}
      />,
    );

    expect(screen.getByText(/Red Agent: Response Error/)).toBeInTheDocument();
    expect(screen.getByText(/not a confirmed absence of vulnerabilities/)).toBeInTheDocument();
    expect(screen.getByText(/Unterminated string/)).toBeInTheDocument();
    expect(screen.queryByText(/No Vulnerability Detected/)).not.toBeInTheDocument();
    expect(screen.queryByText(/No Exploit Found/)).not.toBeInTheDocument();
  });

  it('renders a genuine negative detection as no-vulnerability', () => {
    render(
      <AgentFeed
        streams={[streamFor('ping_host', [redUpdate({ pipeline_status: 'RED_COMPLETE', vulnerability_found: false })])]}
      />,
    );

    expect(screen.getByText(/No Vulnerability Detected/)).toBeInTheDocument();
    expect(screen.queryByText(/Response Error/)).not.toBeInTheDocument();
  });

  it('marks a generated exploit as pending sandbox validation', () => {
    render(
      <AgentFeed
        streams={[
          streamFor('ping_host', [
            redUpdate({
              pipeline_status: 'RED_COMPLETE',
              vulnerability_found: true,
              exploit_code_harness: 'import subprocess\nprint("DEFECT_TRIGGERED")',
              exploit_harness: 'import subprocess\nprint("DEFECT_TRIGGERED")',
              exploit_status: 'AVAILABLE',
            }),
          ]),
        ]}
      />,
    );

    expect(screen.getByText(/Red Agent Attack Payload/)).toBeInTheDocument();
    expect(screen.getByText(/awaiting sandbox validation/)).toBeInTheDocument();
    expect(screen.getByText(/harness validation: AVAILABLE/)).toBeInTheDocument();
  });

  it('shows a preserved diagnosis and the generation failure when no exploit exists', () => {
    render(
      <AgentFeed
        streams={[
          streamFor('ping_host', [
            redUpdate({
              pipeline_status: 'RED_COMPLETE',
              vulnerability_found: true,
              vulnerability_type: 'COMMAND_INJECTION',
              cwe_id: 'CWE-78',
              exploit_harness: null,
              exploit_status: 'UNAVAILABLE',
              exploit_failure_kind: 'EXPLOIT_GENERATION_FAILED',
              exploit_error: 'harness generation was truncated (finish_reason=length)',
            }),
          ]),
        ]}
      />,
    );

    expect(screen.getByTestId('red-diagnosis-no-exploit')).toBeInTheDocument();
    expect(screen.getByText(/cannot be proven secure without one/)).toBeInTheDocument();
    expect(screen.getByText(/EXPLOIT_GENERATION_FAILED/)).toBeInTheDocument();
    expect(screen.getByText(/truncated/)).toBeInTheDocument();
    expect(screen.queryByText(/No Vulnerability Detected/)).not.toBeInTheDocument();
  });

  it('marks a generated patch as awaiting validation and exposes generation errors', () => {
    render(
      <AgentFeed
        streams={[
          streamFor('ping_host', [
            blueUpdate({
              pipeline_status: 'BLUE_COMPLETE',
              patched_code: 'def ping_host(host):\n    return subprocess.run(["ping", host])',
              patch_diff: '--- original\n+++ patched',
              patch_justification: 'Arguments are not interpreted by a shell',
            }),
          ]),
          streamFor('dead_code', [
            blueUpdate({
              pipeline_status: 'BLUE_ERROR',
              patched_code: null,
              error_logs: 'Blue Agent output parse error after 3 attempts',
            }),
          ]),
        ]}
      />,
    );

    expect(screen.getByText(/Blue Agent PATCH_GENERATED/)).toBeInTheDocument();
    expect(screen.getByText(/awaiting sandbox validation/)).toBeInTheDocument();
    expect(screen.getByText(/Patch Generation Error/)).toBeInTheDocument();
    expect(screen.getByText(/parse error after 3 attempts/)).toBeInTheDocument();
  });

  it('shows retry progress when the Judge schedules another attempt', () => {
    render(
      <AgentFeed
        streams={[
          streamFor('ping_host', [
            judgeUpdate({
              pipeline_status: 'RETRY',
              judge_verdict: 'NEW_VULNERABILITY_INTRODUCED',
              error_logs: 'Command injection patch still invokes a shell',
              attempt_number: 1,
              max_attempts: 3,
            }),
          ]),
        ]}
      />,
    );

    expect(screen.getByText(/Retry Scheduled/)).toBeInTheDocument();
    expect(screen.getByText(/retry 2\/3 in progress/)).toBeInTheDocument();
    expect(screen.getAllByText(/NEW_VULNERABILITY_INTRODUCED/).length).toBeGreaterThan(0);
  });

  it('renders the final verdict on the card it belongs to', () => {
    const failed = streamFor('ping_host', [
      { type: 'complete', pipeline_status: 'FAILED', judge_verdict: 'EXPLOIT_NOT_REPRODUCED' },
    ]);
    const passed = streamFor('process_data', [
      redUpdate({ vulnerability_found: true, exploit_harness: 'payload', exploit_status: 'AVAILABLE' }),
      { type: 'complete', pipeline_status: 'COMPLETE', judge_verdict: 'PASS', security_validated: true },
    ]);

    render(<AgentFeed streams={[failed, passed]} />);

    const failedCard = card(failed);
    const passedCard = card(passed);

    expect(within(failedCard).getByText('FAILED')).toBeInTheDocument();
    expect(within(failedCard).getAllByText(/EXPLOIT_NOT_REPRODUCED/).length).toBeGreaterThan(0);
    expect(within(failedCard).queryAllByText('PASS')).toHaveLength(0);

    expect(within(passedCard).getAllByText('PASS').length).toBeGreaterThan(0);
    expect(within(passedCard).queryAllByText(/EXPLOIT_NOT_REPRODUCED/)).toHaveLength(0);
  });

  it('keeps the ML triage score visible when a later agent stage fails', () => {
    render(
      <AgentFeed
        streams={[
          streamFor('ping_host', [
            { type: 'triage_result', score: 92.4, threshold: 65, is_high_risk: true },
            {
              type: 'error',
              stage: 'red_agent',
              message: 'LLM response truncated (finish_reason=length)',
            },
          ]),
        ]}
      />,
    );

    expect(screen.getByText('92.4')).toBeInTheDocument();
    expect(screen.getByText(/ML triage completed and its score above is still valid/)).toBeInTheDocument();
    const errorCard = screen.getByTestId('pipeline-error');
    expect(errorCard).toHaveTextContent('Agent Pipeline Error');
    expect(errorCard).toHaveTextContent('Red Agent');
    expect(errorCard).toHaveTextContent('truncated');
  });

  it('renders a duplicated socket event once', () => {
    const state = {
      pipeline_status: 'RED_COMPLETE',
      vulnerability_found: true,
      exploit_harness: null,
      exploit_status: 'UNAVAILABLE',
      exploit_error: 'the harness must import the workspace target',
    };
    const duplicate = streamFor('ping_host', [redUpdate(state), redUpdate({ ...state })]);

    render(<AgentFeed streams={[duplicate]} />);

    expect(screen.getAllByTestId(/^function-card-/)).toHaveLength(1);
    expect(screen.getAllByTestId('red-diagnosis-no-exploit')).toHaveLength(1);
  });

  it('stacks ML triage, Red, Blue and Judge vertically in one full-width column', () => {
    const stream = streamFor('ping_host', [
      {
        type: 'triage_result',
        score: 42.2,
        threshold: 65,
        is_high_risk: false,
        features: { loc: 18, cyclomatic_complexity: 4, unsafe_func_count: 0 },
      },
    ]);

    render(<AgentFeed streams={[stream]} />);

    const article = card(stream);
    // The previous layout rendered Red/Blue/Judge as three horizontal columns.
    expect(article.querySelector('[class*="grid-cols-3"]')).toBeNull();
    expect(article.className).toContain('w-full');

    const sections = [
      'section-ml-triage',
      'section-red',
      'section-blue',
      'section-judge',
    ].map((testId) => within(article).getByTestId(testId));

    expect(sections).toHaveLength(4);
    for (const section of sections) {
      expect(section.className).toContain('w-full');
    }
    for (let index = 1; index < sections.length; index += 1) {
      expect(
        sections[index - 1].compareDocumentPosition(sections[index]) &
          Node.DOCUMENT_POSITION_FOLLOWING,
      ).toBeTruthy();
    }

    expect(within(article).getByText('42.2')).toBeInTheDocument();
    expect(within(article).getByText('BELOW THRESHOLD')).toBeInTheDocument();
    expect(within(article).getByText(/cyclomatic complexity/)).toBeInTheDocument();
    expect(within(article).getByText('4')).toBeInTheDocument();
    // Zero-valued features are not noise on the card.
    expect(within(article).queryByText(/unsafe C functions/)).not.toBeInTheDocument();
  });

  it('shows the static signal that bypassed the probabilistic model', () => {
    const stream = streamFor('ping_host', [
      {
        type: 'triage_result',
        score: 80.7,
        threshold: 65,
        is_high_risk: true,
        features: {},
        static_signal: 'DYNAMIC_SQL',
      },
    ]);

    render(<AgentFeed streams={[stream]} />);

    expect(screen.getByTestId('triage-static-signal')).toHaveTextContent('dynamic sql');
    expect(screen.getByText(/No extracted features reported/)).toBeInTheDocument();
  });

  it('renders the whole vertical sequence for a function that is still queued', () => {
    const stream = streamFor('queued_function');

    render(<AgentFeed streams={[stream]} />);

    const article = card(stream);
    expect(within(article).getByText('Awaiting ML triage.')).toBeInTheDocument();
    expect(within(article).getByTestId('section-red')).toBeInTheDocument();
    expect(within(article).getByTestId('section-blue')).toBeInTheDocument();
    expect(within(article).getByTestId('section-judge')).toBeInTheDocument();
  });
});
