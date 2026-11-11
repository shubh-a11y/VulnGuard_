import { useEffect, useRef, useState, memo } from 'react';
import { Chart, type ChartConfiguration } from 'chart.js/auto';
import { Brain, Wrench, BarChart2, PieChart } from 'lucide-react';

export interface ChartAnalyticsData {
  total_scans: number;
  ml_classification: {
    accuracy: number;
    precision: number;
    confirmed_vulnerable: number;
    false_alarms: number;
    clean_filtered: number;
    labels: string[];
    data: number[];
  };
  blue_patching: {
    patch_success_rate: number;
    patches_pass: number;
    patches_failed: number;
    unpatched: number;
    total_vulnerabilities: number;
    labels: string[];
    data: number[];
  };
}

interface EvaluationChartsProps {
  apiBase?: string;
  refreshTrigger?: number;
}

export const EvaluationCharts = memo(function EvaluationCharts({
  apiBase = 'http://localhost:8000',
  refreshTrigger = 0,
}: EvaluationChartsProps) {
  const [data, setData] = useState<ChartAnalyticsData | null>(null);
  const [chartType, setChartType] = useState<'doughnut' | 'bar'>('doughnut');
  const [loading, setLoading] = useState(false);

  const mlCanvasRef = useRef<HTMLCanvasElement | null>(null);
  const blueCanvasRef = useRef<HTMLCanvasElement | null>(null);
  const mlChartInstance = useRef<Chart | null>(null);
  const blueChartInstance = useRef<Chart | null>(null);

  // Fetch chart telemetry
  const fetchChartData = async () => {
    try {
      setLoading(true);
      const res = await fetch(`${apiBase}/api/analytics/charts`);
      if (res.ok) {
        const json: ChartAnalyticsData = await res.json();
        setData(json);
      }
    } catch (err) {
      console.warn('Could not load chart analytics:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchChartData();
  }, [refreshTrigger]);

  // Render or update charts
  useEffect(() => {
    if (!data) return;

    // Destroy existing instances
    if (mlChartInstance.current) {
      mlChartInstance.current.destroy();
      mlChartInstance.current = null;
    }
    if (blueChartInstance.current) {
      blueChartInstance.current.destroy();
      blueChartInstance.current = null;
    }

    const hasData = data.total_scans > 0;

    // Chart 1: ML Agent Classification Accuracy & Distribution
    if (mlCanvasRef.current) {
      const mlCtx = mlCanvasRef.current.getContext('2d');
      if (mlCtx) {
        const mlConfig: ChartConfiguration = {
          type: chartType,
          data: {
            labels: data.ml_classification.labels,
            datasets: [
              {
                label: 'Functions',
                data: hasData ? data.ml_classification.data : [0, 0, 0],
                backgroundColor: [
                  'rgba(16, 185, 129, 0.85)', // Verified Vulnerable (TP) - Emerald
                  'rgba(244, 63, 94, 0.85)',  // False Alarms (FP) - Rose
                  'rgba(99, 102, 241, 0.85)', // Safe / Filtered (TN) - Indigo
                ],
                borderColor: [
                  'rgba(16, 185, 129, 1)',
                  'rgba(244, 63, 94, 1)',
                  'rgba(99, 102, 241, 1)',
                ],
                borderWidth: 1.5,
                borderRadius: chartType === 'bar' ? 6 : 0,
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: {
                position: 'bottom',
                labels: {
                  color: 'rgba(255, 255, 255, 0.70)',
                  boxWidth: 12,
                  font: { size: 11 },
                  padding: 12,
                },
              },
              tooltip: {
                backgroundColor: 'rgba(15, 23, 42, 0.90)',
                titleColor: '#fff',
                bodyColor: '#e2e8f0',
                borderColor: 'rgba(255, 255, 255, 0.15)',
                borderWidth: 1,
                padding: 10,
              },
            },
            scales: chartType === 'bar' ? {
              x: {
                ticks: { color: 'rgba(255, 255, 255, 0.60)', font: { size: 10 } },
                grid: { color: 'rgba(255, 255, 255, 0.05)' },
              },
              y: {
                ticks: { color: 'rgba(255, 255, 255, 0.60)', precision: 0 },
                grid: { color: 'rgba(255, 255, 255, 0.05)' },
              },
            } : {},
          },
        };
        mlChartInstance.current = new Chart(mlCtx, mlConfig);
      }
    }

    // Chart 2: Blue Agent Patch Remediation Outcomes
    if (blueCanvasRef.current) {
      const blueCtx = blueCanvasRef.current.getContext('2d');
      if (blueCtx) {
        const blueConfig: ChartConfiguration = {
          type: chartType,
          data: {
            labels: data.blue_patching.labels,
            datasets: [
              {
                label: 'Patches',
                data: hasData ? data.blue_patching.data : [0, 0, 0],
                backgroundColor: [
                  'rgba(34, 197, 94, 0.85)',  // PASS - Green
                  'rgba(245, 158, 11, 0.85)', // Regression / Build Failed - Amber
                  'rgba(148, 163, 184, 0.70)', // Unpatched / Generation Failed - Slate
                ],
                borderColor: [
                  'rgba(34, 197, 94, 1)',
                  'rgba(245, 158, 11, 1)',
                  'rgba(148, 163, 184, 1)',
                ],
                borderWidth: 1.5,
                borderRadius: chartType === 'bar' ? 6 : 0,
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: {
                position: 'bottom',
                labels: {
                  color: 'rgba(255, 255, 255, 0.70)',
                  boxWidth: 12,
                  font: { size: 11 },
                  padding: 12,
                },
              },
              tooltip: {
                backgroundColor: 'rgba(15, 23, 42, 0.90)',
                titleColor: '#fff',
                bodyColor: '#e2e8f0',
                borderColor: 'rgba(255, 255, 255, 0.15)',
                borderWidth: 1,
                padding: 10,
              },
            },
            scales: chartType === 'bar' ? {
              x: {
                ticks: { color: 'rgba(255, 255, 255, 0.60)', font: { size: 10 } },
                grid: { color: 'rgba(255, 255, 255, 0.05)' },
              },
              y: {
                ticks: { color: 'rgba(255, 255, 255, 0.60)', precision: 0 },
                grid: { color: 'rgba(255, 255, 255, 0.05)' },
              },
            } : {},
          },
        };
        blueChartInstance.current = new Chart(blueCtx, blueConfig);
      }
    }

    return () => {
      if (mlChartInstance.current) {
        mlChartInstance.current.destroy();
        mlChartInstance.current = null;
      }
      if (blueChartInstance.current) {
        blueChartInstance.current.destroy();
        blueChartInstance.current = null;
      }
    };
  }, [data, chartType]);

  const mlAccPct = Math.round((data?.ml_classification?.accuracy ?? 0) * 100);
  const mlPrecPct = Math.round((data?.ml_classification?.precision ?? 0) * 100);
  const bluePsrPct = Math.round((data?.blue_patching?.patch_success_rate ?? 0) * 100);

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-xs uppercase tracking-wider text-white/50 font-medium">
            2D Telemetry Visualizations
          </span>
          <span className="rounded-full border border-white/10 bg-white/5 px-2 py-0.5 text-[10px] text-white/60">
            Chart.js
          </span>
          {loading && (
            <span className="text-[10px] text-amber-400/80 animate-pulse">
              Updating...
            </span>
          )}
        </div>

        <div className="flex items-center gap-1 rounded-lg border border-white/10 bg-white/5 p-0.5">
          <button
            type="button"
            onClick={() => setChartType('doughnut')}
            className={`flex items-center gap-1 rounded px-2 py-1 text-xs transition-colors ${
              chartType === 'doughnut'
                ? 'bg-white/15 text-white font-medium shadow-sm'
                : 'text-white/40 hover:text-white/70'
            }`}
          >
            <PieChart className="w-3.5 h-3.5" />
            <span>Donut</span>
          </button>
          <button
            type="button"
            onClick={() => setChartType('bar')}
            className={`flex items-center gap-1 rounded px-2 py-1 text-xs transition-colors ${
              chartType === 'bar'
                ? 'bg-white/15 text-white font-medium shadow-sm'
                : 'text-white/40 hover:text-white/70'
            }`}
          >
            <BarChart2 className="w-3.5 h-3.5" />
            <span>Bar</span>
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Chart 1: ML Agent Classification */}
        <div className="glassmorphism rounded-2xl p-5 border border-white/10 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-purple-500/10 border border-purple-500/20 text-purple-400">
                <Brain className="w-4 h-4" />
              </div>
              <div>
                <h4 className="text-sm font-semibold text-white/90">ML Agent Classification Accuracy</h4>
                <p className="text-xs text-white/40">Triage alignment vs confirmed findings</p>
              </div>
            </div>
            <div className="text-right">
              <span className="text-lg font-bold text-emerald-400">{mlAccPct}%</span>
              <p className="text-[10px] text-white/40">Accuracy ({mlPrecPct}% Prec)</p>
            </div>
          </div>

          <div className="relative h-60 w-full flex items-center justify-center">
            {(!data || data.total_scans === 0) && (
              <div className="absolute inset-0 z-10 flex flex-col items-center justify-center bg-black/40 backdrop-blur-[2px] rounded-xl text-center p-4">
                <p className="text-xs font-medium text-white/70">No scan data recorded yet</p>
                <p className="text-[11px] text-white/40 mt-1">Run a single or batch scan to populate live ML classification telemetry.</p>
              </div>
            )}
            <canvas ref={mlCanvasRef} className="w-full h-full" />
          </div>

          <div className="mt-3 pt-3 border-t border-white/5 flex items-center justify-between text-xs text-white/50">
            <span>Confirmed: <strong className="text-emerald-400">{data?.ml_classification?.confirmed_vulnerable ?? 0}</strong></span>
            <span>False Alarms: <strong className="text-rose-400">{data?.ml_classification?.false_alarms ?? 0}</strong></span>
            <span>Filtered: <strong className="text-indigo-400">{data?.ml_classification?.clean_filtered ?? 0}</strong></span>
          </div>
        </div>

        {/* Chart 2: Blue Agent Patch Outcomes */}
        <div className="glassmorphism rounded-2xl p-5 border border-white/10 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-blue-500/10 border border-blue-500/20 text-blue-400">
                <Wrench className="w-4 h-4" />
              </div>
              <div>
                <h4 className="text-sm font-semibold text-white/90">Blue Agent Patch Remediation</h4>
                <p className="text-xs text-white/40">Validations, regressions & patch outcomes</p>
              </div>
            </div>
            <div className="text-right">
              <span className="text-lg font-bold text-blue-400">{bluePsrPct}%</span>
              <p className="text-[10px] text-white/40">Patch Success (PSR)</p>
            </div>
          </div>

          <div className="relative h-60 w-full flex items-center justify-center">
            {(!data || data.total_scans === 0) && (
              <div className="absolute inset-0 z-10 flex flex-col items-center justify-center bg-black/40 backdrop-blur-[2px] rounded-xl text-center p-4">
                <p className="text-xs font-medium text-white/70">No scan data recorded yet</p>
                <p className="text-[11px] text-white/40 mt-1">Run a scan on vulnerable functions to measure Blue Agent patch validation rates.</p>
              </div>
            )}
            <canvas ref={blueCanvasRef} className="w-full h-full" />
          </div>

          <div className="mt-3 pt-3 border-t border-white/5 flex items-center justify-between text-xs text-white/50">
            <span>Validated PASS: <strong className="text-emerald-400">{data?.blue_patching?.patches_pass ?? 0}</strong></span>
            <span>Validation Failed: <strong className="text-amber-400">{data?.blue_patching?.patches_failed ?? 0}</strong></span>
            <span>Unpatched: <strong className="text-slate-400">{data?.blue_patching?.unpatched ?? 0}</strong></span>
          </div>
        </div>
      </div>
    </div>
  );
});
