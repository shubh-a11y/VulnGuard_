import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import AgentFeed from './AgentFeed';

const selectedFunc = { name: 'ping_host', relative_path: 'vuln_cmdi.py' };

const statusEvent = (message: string) => ({
  type: 'status',
  message,
  function_name: 'ping_host',
});

const redUpdate = (state: Record<string, unknown>) => ({
  type: 'agent_update',
  agent: 'red_agent',
  state,
  function_name: 'ping_host',
});

const blueUpdate = (state: Record<string, unknown>) => ({
  type: 'agent_update',
  agent: 'blue_agent',
  state,
  function_name: 'ping_host',
});

const judgeUpdate = (state: Record<string, unknown>) => ({
  type: 'agent_update',
  agent: 'judge_agent',
  state,
  function_name: 'ping_host',
});

const triageEvent = {
  type: 'triage_result',
  score: 92.4,
  threshold: 65,
  is_high_risk: true,
  function_name: 'ping_host',
};

describe('AgentFeed', () => {
  let scrollIntoViewSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    scrollIntoViewSpy = vi.fn();
    // jsdom does not implement scrollIntoView; install a spy so any leftover
    // auto-scroll call inside the component fails this suite.
    Element.prototype.scrollIntoView = scrollIntoViewSpy as unknown as typeof Element.prototype.scrollIntoView;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('does not auto-scroll when new stream events arrive', () => {
    const { rerender } = render(
      <AgentFeed events={[statusEvent('Starting scan...')]} selectedFunc={selectedFunc} />,
    );
    expect(scrollIntoViewSpy).not.toHaveBeenCalled();

    // Simulate the agents streaming more updates while the read position matters.
    rerender(
      <AgentFeed
        events={[
          statusEvent('Starting scan...'),
          redUpdate({ pipeline_status: 'RED_COMPLETE', vulnerability_found: false }),
          redUpdate({
            pipeline_status: 'RED_COMPLETE',
            vulnerability_found: true,
            exploit_harness: 'import subprocess',
          }),
          judgeUpdate({ pipeline_status: 'COMPLETE', judge_verdict: 'PASS' }),
        ]}
        selectedFunc={selectedFunc}
      />,
    );

    expect(scrollIntoViewSpy).not.toHaveBeenCalled();
  });

  it('does not change the window scroll position on new events', () => {
    const scrollToSpy = vi.fn();
    window.scrollTo = scrollToSpy as unknown as typeof window.scrollTo;

    const { rerender } = render(
      <AgentFeed events={[statusEvent('Starting scan...')]} selectedFunc={selectedFunc} />,
    );
    rerender(
      <AgentFeed
        events={[...Array.from({ length: 20 }, (_, i) => statusEvent(`event ${i}`))]}
        selectedFunc={selectedFunc}
      />,
    );

    expect(scrollToSpy).not.toHaveBeenCalled();
    expect(scrollIntoViewSpy).not.toHaveBeenCalled();
  });

  it('preserves message order and content across renders', () => {
    render(
      <AgentFeed
        events={[
          statusEvent('first message'),
          statusEvent('second message'),
          statusEvent('third message'),
        ]}
        selectedFunc={selectedFunc}
      />,
    );

    const items = screen.getAllByText(/message$/);
    expect(items.map((el) => el.textContent)).toEqual([
      '> first message',
      '> second message',
      '> third message',
    ]);
  });

  it('renders a Red Agent response error as an error, not as a detection result', () => {
    render(
      <AgentFeed
        events={[
          redUpdate({
            pipeline_status: 'RED_ERROR',
            vulnerability_found: false,
            red_report: {
              parse_error: 'schema validation: Unterminated string at line 4',
              raw: '{"vulnerability_found": true, "cwe',
            },
          }),
        ]}
        selectedFunc={selectedFunc}
      />,
    );

    expect(screen.getByText(/Red Agent: Response Error/)).toBeInTheDocument();
    expect(
      screen.getByText(/not a confirmed absence of vulnerabilities/),
    ).toBeInTheDocument();
    expect(screen.getByText(/Unterminated string/)).toBeInTheDocument();
    expect(screen.queryByText(/No Vulnerability Detected/)).not.toBeInTheDocument();
    expect(screen.queryByText(/No Exploit Found/)).not.toBeInTheDocument();
  });

  it('renders a genuine negative detection as no-vulnerability', () => {
    render(
      <AgentFeed
        events={[
          redUpdate({ pipeline_status: 'RED_COMPLETE', vulnerability_found: false }),
        ]}
        selectedFunc={selectedFunc}
      />,
    );

    expect(screen.getByText(/No Vulnerability Detected/)).toBeInTheDocument();
    expect(screen.queryByText(/Response Error/)).not.toBeInTheDocument();
  });

  it('marks a generated exploit as pending sandbox validation', () => {
    render(
      <AgentFeed
        events={[
          redUpdate({
            pipeline_status: 'RED_COMPLETE',
            vulnerability_found: true,
            exploit_harness: 'import subprocess\nprint("DEFECT_TRIGGERED")',
          }),
        ]}
        selectedFunc={selectedFunc}
      />,
    );

    expect(screen.getByText(/Red Agent Attack Payload/)).toBeInTheDocument();
    expect(screen.getByText(/awaiting sandbox validation/)).toBeInTheDocument();
  });

  it('marks a generated patch as awaiting validation and exposes generation errors', () => {
    render(
      <AgentFeed
        events={[
          blueUpdate({
            pipeline_status: 'BLUE_COMPLETE',
            patched_code: 'def ping_host(host):\n    return subprocess.run(["ping", host])',
            patch_diff: '--- original\n+++ patched',
            patch_justification: 'Arguments are not interpreted by a shell',
          }),
          blueUpdate({
            pipeline_status: 'BLUE_ERROR',
            patched_code: null,
            error_logs: 'Blue Agent output parse error after 3 attempts',
          }),
        ]}
        selectedFunc={selectedFunc}
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
        events={[
          judgeUpdate({
            pipeline_status: 'RETRY',
            judge_verdict: 'NEW_VULNERABILITY_INTRODUCED',
            error_logs: 'Command injection patch still invokes a shell',
            attempt_number: 1,
            max_attempts: 3,
          }),
        ]}
        selectedFunc={selectedFunc}
      />,
    );

    expect(screen.getByText(/Retry Scheduled/)).toBeInTheDocument();
    expect(screen.getByText(/retry 2\/3 in progress/)).toBeInTheDocument();
    expect(screen.getByText(/NEW_VULNERABILITY_INTRODUCED/)).toBeInTheDocument();
  });

  it('keeps the ML triage score visible when a later agent stage fails', () => {
    render(
      <AgentFeed
        events={[
          triageEvent,
          {
            type: 'error',
            stage: 'red_agent',
            message: 'LLM response truncated (finish_reason=length)',
            function_name: 'ping_host',
          },
        ]}
        selectedFunc={selectedFunc}
      />,
    );

    // The triage card survives the later failure and still shows its score.
    expect(screen.getByText('92.4')).toBeInTheDocument();
    expect(screen.getByText(/ML triage completed and its score above is still valid/)).toBeInTheDocument();
    // The error is scoped to the failing agent stage, not to triage.
    const errorCard = screen.getByTestId('pipeline-error');
    expect(errorCard).toHaveTextContent('Agent Pipeline Error');
    expect(errorCard).toHaveTextContent('Red Agent');
    expect(errorCard).toHaveTextContent('truncated');
  });

  it('shows a preserved diagnosis when the exploit could not be generated', () => {
    render(
      <AgentFeed
        events={[
          redUpdate({
            pipeline_status: 'RED_COMPLETE',
            vulnerability_found: true,
            exploit_harness: null,
            exploit_status: 'INVALID',
            exploit_error: 'the harness must import the workspace target',
          }),
        ]}
        selectedFunc={selectedFunc}
      />,
    );

    expect(screen.getByTestId('red-diagnosis-no-exploit')).toBeInTheDocument();
    expect(screen.getByText(/cannot be proven secure without one/)).toBeInTheDocument();
    expect(screen.getByText(/must import the workspace target/)).toBeInTheDocument();
    expect(screen.queryByText(/No Vulnerability Detected/)).not.toBeInTheDocument();
  });

  it('renders the final scan status from the complete event', () => {
    render(
      <AgentFeed
        events={[
          {
            type: 'complete',
            pipeline_status: 'FAILED',
            judge_verdict: 'EXPLOIT_NOT_REPRODUCED',
            function_name: 'ping_host',
          },
        ]}
        selectedFunc={selectedFunc}
      />,
    );

    expect(screen.getByText(/scan finished/)).toBeInTheDocument();
    expect(screen.getByText('FAILED')).toBeInTheDocument();
    expect(screen.getByText(/EXPLOIT_NOT_REPRODUCED/)).toBeInTheDocument();
  });

  it('renders a confirmed pass verdict without retry wording', () => {
    render(
      <AgentFeed
        events={[
          judgeUpdate({
            pipeline_status: 'COMPLETE',
            judge_verdict: 'PASS',
          }),
        ]}
        selectedFunc={selectedFunc}
      />,
    );

    expect(screen.getByText(/Judge Agent Verdict/)).toBeInTheDocument();
    expect(screen.getByText('PASS')).toBeInTheDocument();
    expect(screen.queryByText(/Retry Scheduled/)).not.toBeInTheDocument();
  });
});
