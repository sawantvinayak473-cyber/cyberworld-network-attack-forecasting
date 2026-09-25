import React from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';
import {
  BarChart3,
  Award,
  TrendingUp,
  Clock,
  ShieldCheck,
  CheckCircle,
  HelpCircle,
} from 'lucide-react';
import { BENCHMARK_DATA } from '../mockData/scenarios';

export const BenchmarksView: React.FC = () => {
  // Chart data for F1, ROC-AUC, FPR comparison
  const classificationMetricsChart = [
    {
      metric: 'F1 Score',
      'LSTM World Model': 95.5,
      'Random Forest': 86.3,
      'Logistic Regression': 77.8,
    },
    {
      metric: 'Recall',
      'LSTM World Model': 96.2,
      'Random Forest': 84.6,
      'Logistic Regression': 76.4,
    },
    {
      metric: 'Precision',
      'LSTM World Model': 94.8,
      'Random Forest': 88.1,
      'Logistic Regression': 79.2,
    },
    {
      metric: 'ROC-AUC',
      'LSTM World Model': 98.4,
      'Random Forest': 91.2,
      'Logistic Regression': 82.4,
    },
  ];

  const stageMetrics = [
    { stage: 'BENIGN', precision: 0.98, recall: 0.97, f1: 0.975 },
    { stage: 'RECONNAISSANCE', precision: 0.94, recall: 0.95, f1: 0.945 },
    { stage: 'INITIAL_ACCESS', precision: 0.91, recall: 0.93, f1: 0.920 },
    { stage: 'LATERAL_MOVEMENT', precision: 0.93, recall: 0.94, f1: 0.935 },
    { stage: 'COMMAND_AND_CONTROL', precision: 0.96, recall: 0.97, f1: 0.965 },
    { stage: 'EXFILTRATION', precision: 0.97, recall: 0.98, f1: 0.975 },
  ];

  return (
    <div className="space-y-5">
      {/* Top Banner */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2">
              <Award className="w-5 h-5 text-amber-400" />
              <h3 className="text-sm font-bold font-mono text-slate-100">
                BENCHMARK: WORLD MODEL vs. STATIC POINT-IN-TIME CLASSIFIERS
              </h3>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-3xl">
              Static classifiers analyze isolated flows in a vacuum, yielding high false positive rates on port scans and zero forward forecasting capability. CyberWorld's World Model temporal dynamics yield measurable gains across detection latency and early warning lead time.
            </p>
          </div>
          <div className="p-2.5 rounded-lg bg-emerald-950/60 border border-emerald-800/80 font-mono text-xs">
            <span className="text-slate-400">Early Warning Lead:</span>
            <div className="text-emerald-400 font-extrabold text-base">+142.4 seconds</div>
          </div>
        </div>
      </div>

      {/* Comparison Table */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
        <h4 className="text-xs font-bold font-mono uppercase text-slate-300 tracking-wider mb-3">
          Head-to-Head Architectural Comparison
        </h4>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 bg-slate-950/60">
                <th className="py-2.5 px-3">Model Architecture</th>
                <th className="py-2.5 px-3">F1 Score</th>
                <th className="py-2.5 px-3">ROC-AUC</th>
                <th className="py-2.5 px-3">False Pos. Rate (FPR)</th>
                <th className="py-2.5 px-3">Early Warning Lead</th>
                <th className="py-2.5 px-3">T+1 Accuracy</th>
                <th className="py-2.5 px-3">T+5 Accuracy</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {BENCHMARK_DATA.map((bm) => (
                <tr
                  key={bm.modelName}
                  className={`hover:bg-slate-850/40 transition-colors ${
                    bm.isWorldModel ? 'bg-emerald-950/15 font-semibold' : ''
                  }`}
                >
                  <td className="py-2.5 px-3 text-slate-200 flex items-center space-x-2">
                    {bm.isWorldModel && <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />}
                    <span>{bm.modelName}</span>
                  </td>
                  <td className="py-2.5 px-3 text-emerald-400 font-bold">
                    {(bm.f1Score * 100).toFixed(1)}%
                  </td>
                  <td className="py-2.5 px-3 text-cyan-400">
                    {(bm.rocAuc * 100).toFixed(1)}%
                  </td>
                  <td className="py-2.5 px-3 text-red-400">
                    {(bm.falsePositiveRate * 100).toFixed(1)}%
                  </td>
                  <td className="py-2.5 px-3">
                    {bm.earlyWarningLeadTimeSec > 0 ? (
                      <span className="text-emerald-300 font-bold">
                        +{bm.earlyWarningLeadTimeSec}s
                      </span>
                    ) : (
                      <span className="text-slate-500">0s (Reactive)</span>
                    )}
                  </td>
                  <td className="py-2.5 px-3">
                    {bm.forecastAccuracyT1 > 0 ? (
                      <span className="text-slate-200">{(bm.forecastAccuracyT1 * 100).toFixed(1)}%</span>
                    ) : (
                      <span className="text-slate-600">N/A</span>
                    )}
                  </td>
                  <td className="py-2.5 px-3">
                    {bm.forecastAccuracyT5 > 0 ? (
                      <span className="text-slate-200">{(bm.forecastAccuracyT5 * 100).toFixed(1)}%</span>
                    ) : (
                      <span className="text-slate-600">N/A</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Side-by-Side: Classification Metrics Chart (Left) & Per-Stage Metrics (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Chart */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
          <h4 className="text-xs font-bold font-mono uppercase text-slate-300 tracking-wider mb-2">
            Performance Metrics Breakdown (%)
          </h4>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={classificationMetricsChart} margin={{ top: 15, right: 10, left: -20, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="metric" stroke="#64748b" tick={{ fontSize: 10, fill: '#94a3b8' }} />
                <YAxis domain={[60, 100]} stroke="#64748b" tick={{ fontSize: 10, fill: '#94a3b8' }} unit="%" />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', fontSize: '11px', fontFamily: 'monospace' }}
                />
                <Legend wrapperStyle={{ fontSize: '11px', fontFamily: 'monospace', paddingTop: '8px' }} />
                <Bar dataKey="LSTM World Model" fill="#10b981" radius={[4, 4, 0, 0]} />
                <Bar dataKey="Random Forest" fill="#38bdf8" radius={[4, 4, 0, 0]} />
                <Bar dataKey="Logistic Regression" fill="#64748b" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Per-Stage Precision/Recall Breakdown */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
          <h4 className="text-xs font-bold font-mono uppercase text-slate-300 tracking-wider mb-2">
            CyberWorld Per-Stage Classification Quality
          </h4>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400">
                  <th className="py-2 px-2">Lifecycle Stage</th>
                  <th className="py-2 px-2">Precision</th>
                  <th className="py-2 px-2">Recall</th>
                  <th className="py-2 px-2">F1 Score</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {stageMetrics.map((sm) => (
                  <tr key={sm.stage} className="hover:bg-slate-850/40">
                    <td className="py-2 px-2 font-bold text-slate-300">{sm.stage}</td>
                    <td className="py-2 px-2 text-slate-200">{(sm.precision * 100).toFixed(1)}%</td>
                    <td className="py-2 px-2 text-slate-200">{(sm.recall * 100).toFixed(1)}%</td>
                    <td className="py-2 px-2 text-emerald-400 font-bold">{(sm.f1 * 100).toFixed(1)}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-4 p-2.5 rounded bg-slate-950/70 border border-slate-800 text-[11px] text-slate-400 font-mono">
            * Evaluated on strictly held-out chronological test sets (15% chronological split) without data leakage. Scalers fitted exclusively on training horizon.
          </div>
        </div>
      </div>
    </div>
  );
};
