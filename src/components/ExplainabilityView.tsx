import React, { useMemo, useState } from 'react';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { Cpu, Info, LoaderCircle, Sparkles } from 'lucide-react';
import type { CopilotContext } from '../api/copilotApi';
import { askCopilot } from '../api/copilotApi';
import { FeatureAttribution, NetworkStateVector } from '../types';

interface ExplainabilityViewProps {
  attributions: FeatureAttribution[];
  currentWindow: number;
  currentState: NetworkStateVector;
  attackProbability: number;
  copilotContext: Omit<CopilotContext, 'conversationHistory'>;
}

const BASELINE_PROBABILITY = 0.08;
const ATTENTION_CATEGORIES: FeatureAttribution['category'][] = [
  'FLAGS',
  'TIMING',
  'TOPOLOGY',
  'VOLUME',
  'PACKET',
];
const ATTENTION_WINDOWS = ['S(t-4)', 'S(t-3)', 'S(t-2)', 'S(t-1)', 'S(t)'];

const COUNTERFACTUAL_THRESHOLDS: Record<string, string> = {
  syn_ack_ratio: '1.20x',
  port_diversity: '50.0%',
  iat_variance: '500 ms²',
  burstiness_index: '0.60',
  rst_flow_ratio: '10.0%',
  packet_size_entropy: '4.50 bits',
};

function clampProbability(value: number): number {
  return Math.min(1, Math.max(0, value));
}

export const ExplainabilityView: React.FC<ExplainabilityViewProps> = ({
  attributions,
  currentWindow,
  currentState,
  attackProbability,
  copilotContext,
}) => {
  const [managementExplanation, setManagementExplanation] = useState('');
  const [isExplainingToManagement, setIsExplainingToManagement] = useState(false);
  const [managementError, setManagementError] = useState('');

  const sortedAttributions = useMemo(
    () => [...attributions].sort((left, right) => Math.abs(right.contribution) - Math.abs(left.contribution)),
    [attributions],
  );

  const { waterfallData, finalProbability } = useMemo(() => {
    let cumulativeProbability = BASELINE_PROBABILITY;
    const data = [{
      name: 'Baseline (BENIGN)',
      start: 0,
      magnitude: BASELINE_PROBABILITY * 100,
      contribution: null as number | null,
      value: '0.08',
      category: 'BASELINE',
      color: '#38bdf8',
    }];

    for (const attribution of sortedAttributions) {
      const nextProbability = clampProbability(cumulativeProbability + attribution.contribution);
      data.push({
        name: attribution.displayName,
        start: Math.min(cumulativeProbability, nextProbability) * 100,
        magnitude: Math.abs(nextProbability - cumulativeProbability) * 100,
        contribution: attribution.contribution,
        value: attribution.formattedValue,
        category: attribution.category,
        color: attribution.contribution >= 0 ? '#ef4444' : '#10b981',
      });
      cumulativeProbability = nextProbability;
    }

    const finalProbability = clampProbability(cumulativeProbability);
    data.push({
      name: 'Final probability sum',
      start: 0,
      magnitude: finalProbability * 100,
      contribution: null,
      value: `${(finalProbability * 100).toFixed(1)}%`,
      category: 'FINAL',
      color: '#f59e0b',
    });

    return { waterfallData: data, finalProbability };
  }, [sortedAttributions]);

  const attentionHeatmap = useMemo(() => ATTENTION_CATEGORIES.map((category) => {
    const categoryMagnitude = attributions
      .filter((attribution) => attribution.category === category)
      .reduce((sum, attribution) => sum + Math.abs(attribution.contribution), 0);
    const attributionStrength = Math.min(1, categoryMagnitude / 0.45);

    return {
      category,
      cells: ATTENTION_WINDOWS.map((window, index) => {
        const recency = 0.35 + ((index + 1) / ATTENTION_WINDOWS.length) * 0.65;
        const weight = Math.min(1, (0.12 + attributionStrength * 0.88) * recency);
        return { window, weight: Number(weight.toFixed(2)) };
      }),
    };
  }), [attributions]);

  const topRiskFeature = sortedAttributions.find((attribution) => attribution.contribution > 0)
    ?? sortedAttributions[0];
  const reducedProbability = topRiskFeature
    ? clampProbability(attackProbability - topRiskFeature.contribution)
    : attackProbability;
  const counterfactualThreshold = topRiskFeature
    ? COUNTERFACTUAL_THRESHOLDS[topRiskFeature.featureName] ?? topRiskFeature.formattedValue
    : '';

  const explainToManagement = async () => {
    if (isExplainingToManagement) return;

    setIsExplainingToManagement(true);
    setManagementError('');
    try {
      const response = await askCopilot(
        `Explain in 3 plain sentences suitable for a CISO why this network window was flagged as high risk. Use the following feature attributions: ${JSON.stringify(attributions)}. Avoid technical jargon.`,
        { ...copilotContext, conversationHistory: [] },
      );
      setManagementExplanation(response);
    } catch {
      setManagementError('Copilot is unavailable. Check the API key in .env and try again.');
    } finally {
      setIsExplainingToManagement(false);
    }
  };

  return (
    <div className="space-y-5">
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <div className="flex items-center space-x-2">
              <Cpu className="w-5 h-5 text-emerald-400" />
              <h3 className="text-sm font-bold font-mono text-slate-100">EXPLAINABILITY CENTER</h3>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-3xl">
              Feature attribution and temporal attention show both the signals and the time windows that drove this risk assessment.
            </p>
          </div>
          <div className="text-right text-xs font-mono">
            <span className="text-slate-400">Current Infiltration Risk:</span>
            <div className="text-xl font-bold text-red-400">{(attackProbability * 100).toFixed(1)}%</div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
        <section className="xl:col-span-2 bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between mb-3">
            <div>
              <h4 className="text-xs font-bold font-mono uppercase text-slate-300 tracking-wider">
                SHAP Waterfall — Current Window #{currentWindow + 1}
              </h4>
              <p className="text-[11px] text-slate-400">
                Features are ordered by attribution magnitude, starting from the 8.0% benign baseline.
              </p>
            </div>
            <span className="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-[10px] font-mono text-amber-300">
              Sum: {(finalProbability * 100).toFixed(1)}%
            </span>
          </div>

          <div className="h-[330px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart layout="vertical" data={waterfallData} margin={{ top: 5, right: 18, left: 145, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis
                  type="number"
                  stroke="#64748b"
                  tick={{ fontSize: 10, fill: '#94a3b8' }}
                  tickFormatter={(value) => `${Number(value).toFixed(0)}%`}
                />
                <YAxis
                  type="category"
                  dataKey="name"
                  width={135}
                  stroke="#64748b"
                  tick={{ fontSize: 9, fill: '#cbd5e1' }}
                />
                <Tooltip
                  content={({ active, payload }) => {
                    if (active && payload?.length) {
                      const data = payload[0].payload;
                      return (
                        <div className="rounded-lg border border-slate-700 bg-slate-900 p-2.5 text-xs font-mono shadow-xl">
                          <div className="mb-1 font-bold text-slate-200">{data.name}</div>
                          {data.contribution !== null ? (
                            <>
                              <div className="text-slate-400">Observed value: {data.value}</div>
                              <div className={data.contribution >= 0 ? 'font-bold text-red-400' : 'font-bold text-emerald-400'}>
                                Contribution: {data.contribution >= 0 ? '+' : ''}{(data.contribution * 100).toFixed(1)}%
                              </div>
                            </>
                          ) : (
                            <div className="font-bold text-cyan-400">Probability: {data.value}</div>
                          )}
                        </div>
                      );
                    }
                    return null;
                  }}
                />
                <ReferenceLine x={0} stroke="#475569" strokeWidth={1.5} />
                <Bar dataKey="start" stackId="waterfall" fill="transparent" legendType="none" />
                <Bar dataKey="magnitude" stackId="waterfall" radius={[0, 4, 4, 0]}>
                  {waterfallData.map((entry) => <Cell key={entry.name} fill={entry.color} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="flex flex-wrap gap-x-4 gap-y-1 border-t border-slate-800 pt-2 text-xs font-mono">
            <span className="text-red-400"><span className="mr-1 inline-block h-2.5 w-2.5 rounded bg-red-500" />Risk-increasing feature</span>
            <span className="text-emerald-400"><span className="mr-1 inline-block h-2.5 w-2.5 rounded bg-emerald-500" />Risk-reducing feature</span>
            <span className="text-cyan-400"><span className="mr-1 inline-block h-2.5 w-2.5 rounded bg-cyan-400" />Baseline</span>
          </div>
        </section>

        <section className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
          <h4 className="text-xs font-bold font-mono uppercase text-slate-300 tracking-wider">Executive Explanation</h4>
          <p className="mt-1 text-[11px] text-slate-400">Turn the attribution evidence into a concise, CISO-ready summary.</p>
          <button
            type="button"
            onClick={() => void explainToManagement()}
            disabled={isExplainingToManagement}
            className="mt-4 flex w-full items-center justify-center gap-2 rounded-lg border border-emerald-700 bg-emerald-950/50 px-3 py-2 text-xs font-bold text-emerald-300 transition-colors hover:bg-emerald-900/50 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {isExplainingToManagement ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <Sparkles className="h-3.5 w-3.5" />}
            {isExplainingToManagement ? 'Writing summary…' : 'Explain to management'}
          </button>
          {managementError && <p className="mt-3 text-xs font-mono text-amber-400">{managementError}</p>}
          {managementExplanation && (
            <blockquote className="mt-4 border-l-2 border-emerald-500 bg-emerald-950/20 px-3 py-3 text-sm leading-6 text-slate-200">
              {managementExplanation}
            </blockquote>
          )}

          <div className="mt-5 border-t border-slate-800 pt-4">
            <div className="flex items-center gap-2">
              <Info className="h-4 w-4 text-cyan-400" />
              <h4 className="text-xs font-bold font-mono uppercase text-slate-300 tracking-wider">Counterfactual</h4>
            </div>
            {topRiskFeature ? (
              <p className="mt-2 text-xs leading-5 text-slate-400">
                If <span className="font-semibold text-slate-200">{topRiskFeature.displayName}</span> had been <span className="font-semibold text-emerald-300">{counterfactualThreshold}</span> instead of <span className="font-semibold text-slate-200">{topRiskFeature.formattedValue}</span>, attack probability would be approximately <span className="font-bold text-emerald-300">{(reducedProbability * 100).toFixed(1)}%</span>.
              </p>
            ) : (
              <p className="mt-2 text-xs text-slate-500">No feature attribution is available for this window.</p>
            )}
          </div>
        </section>
      </div>

      <section className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between mb-4">
          <div>
            <h4 className="text-xs font-bold font-mono uppercase text-slate-300 tracking-wider">Temporal Attention Heatmap</h4>
            <p className="mt-1 text-xs text-slate-400">Derived from attribution strength and recency decay across the latest five network states.</p>
          </div>
          <span className="text-[10px] font-mono text-slate-500">Window timestamp: {currentState.timestamp}</span>
        </div>

        <div className="grid grid-cols-[100px_repeat(5,minmax(0,1fr))] gap-1.5 text-center font-mono text-[10px]">
          <div />
          {ATTENTION_WINDOWS.map((window) => <div key={window} className="pb-1 text-slate-400">{window}</div>)}
          {attentionHeatmap.flatMap((row) => [
            <div key={`${row.category}-label`} className="flex items-center text-left font-bold text-slate-300">{row.category}</div>,
            ...row.cells.map((cell) => {
              const alpha = 0.08 + cell.weight * 0.72;
              return (
                <div
                  key={`${row.category}-${cell.window}`}
                  title={`${row.category}, ${cell.window}: ${(cell.weight * 100).toFixed(0)}% attention`}
                  className={`flex min-h-12 items-center justify-center rounded border border-emerald-900/50 ${cell.weight > 0.63 ? 'text-slate-950' : 'text-emerald-100'}`}
                  style={{ backgroundColor: `rgba(16, 185, 129, ${alpha})` }}
                >
                  {(cell.weight * 100).toFixed(0)}%
                </div>
              );
            }),
          ])}
        </div>
        <div className="mt-3 flex items-center gap-2 text-[10px] font-mono text-slate-500">
          <span>Lower attention</span>
          <span className="h-2 w-24 rounded" style={{ background: 'linear-gradient(90deg, rgba(16,185,129,0.1), rgba(16,185,129,0.8))' }} />
          <span>Higher attention</span>
        </div>
      </section>
    </div>
  );
};
