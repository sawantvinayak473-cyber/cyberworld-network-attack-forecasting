import React, { useState } from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from 'recharts';
import {
  ShieldAlert,
  ArrowRight,
  TrendingUp,
  AlertTriangle,
  Flame,
  CheckCircle,
  ExternalLink,
  Zap,
  Info,
  ChevronDown,
} from 'lucide-react';
import {
  AttackStage,
  ForecastStep,
  FeatureAttribution,
  MitreTechniqueCandidate,
  NetworkStateVector,
  Alert,
} from '../types';
import { ATTACK_STAGE_INFO } from '../mockData/scenarios';
import type { ResidualAnomalyResult } from '../engine/worldModelSimulator';

interface DashboardViewProps {
  currentWindow: number;
  allStates: NetworkStateVector[];
  attackProbability: number;
  currentStage: AttackStage;
  predictedNextStage: AttackStage;
  forecasts: ForecastStep[];
  attributions: FeatureAttribution[];
  mitreCandidates: MitreTechniqueCandidate[];
  alerts: Alert[];
  residualAnomaly: ResidualAnomalyResult;
  onNavigateTab: (tab: string) => void;
  onSelectAlertForInvestigation: (alert: Alert) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  currentWindow,
  allStates,
  attackProbability,
  currentStage,
  predictedNextStage,
  forecasts,
  attributions,
  mitreCandidates,
  alerts,
  residualAnomaly,
  onNavigateTab,
  onSelectAlertForInvestigation,
}) => {
  const [isResidualPanelOpen, setIsResidualPanelOpen] = useState(true);
  const killChainStages: AttackStage[] = [
    'BENIGN',
    'RECONNAISSANCE',
    'INITIAL_ACCESS',
    'LATERAL_MOVEMENT',
    'COMMAND_AND_CONTROL',
    'EXFILTRATION',
  ];

  // Prepare chart data for temporal evolution up to current window + future forecast
  const chartData = allStates.slice(0, currentWindow + 1).map((s, idx) => {
    let prob = 0.05;
    if (s.groundTruthStage === 'RECONNAISSANCE') prob = 0.65;
    else if (s.groundTruthStage === 'INITIAL_ACCESS') prob = 0.86;
    else if (s.groundTruthStage === 'LATERAL_MOVEMENT') prob = 0.94;
    else if (s.groundTruthStage === 'COMMAND_AND_CONTROL') prob = 0.97;
    else if (s.groundTruthStage === 'EXFILTRATION') prob = 0.99;
    else if (idx >= currentWindow - 2 && attackProbability > 0.3) prob = attackProbability;

    return {
      name: `T-${(currentWindow - idx) * 10}s`,
      timeSec: idx * 10,
      timestamp: s.timestamp,
      attackProb: Number((prob * 100).toFixed(1)),
      stage: s.groundTruthStage,
      isForecast: false,
    };
  });

  // Append forward forecast steps
  forecasts.slice(0, 5).forEach((f) => {
    chartData.push({
      name: `T+${f.horizonSeconds}s`,
      timeSec: (currentWindow + f.step) * 10,
      timestamp: `+${f.horizonSeconds}s`,
      attackProb: Number((f.attackProbability * 100).toFixed(1)),
      stage: f.predictedStage,
      isForecast: true,
    });
  });

  const getStageIndex = (st: AttackStage) => killChainStages.indexOf(st);
  const currentStageIdx = getStageIndex(currentStage);
  const predictedNextStageIdx = getStageIndex(predictedNextStage);

  return (
    <div className="space-y-5">
      {/* Top Banner: Core Value Proposition */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-900 to-slate-850 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-3 shadow-md">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-lg bg-emerald-950/60 border border-emerald-800/40 text-emerald-400">
            <Zap className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-100 flex items-center space-x-2">
              <span>Predictive Cyber Defence via World Models</span>
              <span className="text-[10px] uppercase font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
                P(S_t+1 | S_t)
              </span>
            </h3>
            <p className="text-xs text-slate-400">
              Unlike static single-packet classifiers, CyberWorld simulates multi-step forward state trajectories to preemptively flag lateral movement and C2 before compromise completion.
            </p>
          </div>
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={() => onNavigateTab('live-monitor')}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-750 text-slate-200 border border-slate-700 text-xs font-mono flex items-center space-x-1.5 transition-colors"
          >
            <span>Launch Live Replay</span>
            <ArrowRight className="w-3.5 h-3.5 text-cyan-400" />
          </button>
        </div>
      </div>

      {residualAnomaly.isAnomaly && (
        <section className="overflow-hidden rounded-xl border border-amber-500/50 bg-amber-950/20 shadow-sm">
          <button
            type="button"
            onClick={() => setIsResidualPanelOpen((open) => !open)}
            aria-expanded={isResidualPanelOpen}
            className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left hover:bg-amber-500/5 transition-colors"
          >
            <span className="flex items-center gap-2 min-w-0">
              <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400 animate-pulse" />
              <span>
                <span className="block text-xs font-bold font-mono uppercase tracking-wider text-amber-200">
                  Residual Anomaly — {residualAnomaly.anomalyType.replace(/_/g, ' ')}
                </span>
                <span className="block mt-0.5 text-[11px] text-amber-100/70">
                  Prediction residual score: {residualAnomaly.residualScore.toFixed(2)}
                </span>
              </span>
            </span>
            <ChevronDown className={`h-4 w-4 shrink-0 text-amber-300 transition-transform ${isResidualPanelOpen ? 'rotate-180' : ''}`} />
          </button>

          {isResidualPanelOpen && (
            <div className="border-t border-amber-500/25 px-4 py-3">
              <p className="mb-3 text-xs text-amber-100/85">{residualAnomaly.interpretation}</p>
              <div className="overflow-x-auto rounded-lg border border-amber-500/20">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-950/50 text-[10px] uppercase tracking-wider text-amber-200/70">
                    <tr>
                      <th className="px-3 py-2 font-semibold">Feature</th>
                      <th className="px-3 py-2 font-semibold">Predicted</th>
                      <th className="px-3 py-2 font-semibold">Actual</th>
                      <th className="px-3 py-2 font-semibold">Deviation</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-amber-500/10 text-slate-200">
                    {residualAnomaly.surprisedFeatures.map((feature) => (
                      <tr key={feature.featureName}>
                        <td className="px-3 py-2 font-semibold text-slate-100">{feature.displayName}</td>
                        <td className="px-3 py-2 text-slate-400">{feature.predicted.toFixed(2)}</td>
                        <td className="px-3 py-2 text-amber-100">{feature.actual.toFixed(2)}</td>
                        <td className="px-3 py-2 text-amber-300">{(feature.deviation * 100).toFixed(1)}%</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </section>
      )}

      {/* Attack Kill-Chain Progression Pipeline */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center space-x-2">
            <h4 className="text-xs font-bold font-mono uppercase text-slate-300 tracking-wider">
              Attack Lifecycle Kill-Chain Mapping
            </h4>
            <span className="text-[10px] text-slate-400 font-mono">
              (Observed vs. Forward Forecasted)
            </span>
          </div>
          <div className="flex items-center space-x-3 text-[11px] font-mono">
            <span className="flex items-center space-x-1 text-emerald-400">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
              <span>Current Observed</span>
            </span>
            <span className="flex items-center space-x-1 text-cyan-400">
              <span className="w-2.5 h-2.5 rounded-full bg-cyan-500 border border-cyan-300 animate-pulse" />
              <span>Predicted Horizon</span>
            </span>
          </div>
        </div>

        {/* Pipeline Nodes */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
          {killChainStages.map((stage, idx) => {
            const info = ATTACK_STAGE_INFO[stage];
            const isObserved = idx <= currentStageIdx && currentStageIdx >= 0;
            const isCurrent = idx === currentStageIdx;
            const isPredicted = idx === predictedNextStageIdx && !isCurrent;
            const isFuture = idx > Math.max(currentStageIdx, predictedNextStageIdx);

            return (
              <div
                key={stage}
                className={`relative rounded-lg p-2.5 border transition-all ${
                  isCurrent
                    ? 'border-emerald-500 bg-emerald-950/40 ring-1 ring-emerald-500 shadow-lg shadow-emerald-950/50'
                    : isPredicted
                    ? 'border-cyan-500 bg-cyan-950/40 ring-1 ring-cyan-500/80 shadow-md shadow-cyan-950/30'
                    : isObserved
                    ? 'border-slate-700 bg-slate-850/60 opacity-80'
                    : 'border-slate-800/80 bg-slate-900/30 opacity-40'
                }`}
              >
                <div className="flex items-center justify-between text-[10px] font-mono mb-1">
                  <span className="text-slate-400">Step {idx + 1}</span>
                  {isCurrent && (
                    <span className="px-1.5 py-0.2 rounded text-[9px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-bold">
                      ACTIVE
                    </span>
                  )}
                  {isPredicted && (
                    <span className="px-1.5 py-0.2 rounded text-[9px] bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-bold animate-pulse">
                      FORECAST
                    </span>
                  )}
                </div>
                <div
                  className="text-xs font-bold font-mono truncate"
                  style={{ color: isCurrent || isPredicted ? info.color : '#94a3b8' }}
                >
                  {stage.replace(/_/g, ' ')}
                </div>
                <div className="text-[10px] text-slate-400 truncate mt-1">
                  {info.label}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Main Row: Live Timeline Chart & Forward Simulation Horizon */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Live Attack Probability Timeline (2 Cols) */}
        <div className="lg:col-span-2 bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <div>
                <h4 className="text-xs font-bold font-mono uppercase text-slate-300 tracking-wider flex items-center space-x-2">
                  <span>Attack Probability Timeline & Forward Simulation</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                    Autoregressive Rollout
                  </span>
                </h4>
                <p className="text-xs text-slate-400 mt-0.5">
                  Solid area represents observed 10s windows; dashed line represents model forward forecast rollouts.
                </p>
              </div>
              <div className="text-right font-mono text-xs text-slate-400">
                <span>Window Duration: </span>
                <span className="text-emerald-400 font-bold">10s</span>
              </div>
            </div>

            {/* Recharts Area Chart */}
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="attackProbGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="name" stroke="#64748b" tick={{ fontSize: 10, fill: '#94a3b8' }} />
                  <YAxis domain={[0, 100]} stroke="#64748b" tick={{ fontSize: 10, fill: '#94a3b8' }} unit="%" />
                  <Tooltip
                    content={({ active, payload }) => {
                      if (active && payload && payload.length) {
                        const data = payload[0].payload;
                        return (
                          <div className="bg-slate-900 border border-slate-700 p-2.5 rounded-lg shadow-xl text-xs font-mono">
                            <div className="text-slate-400 font-semibold mb-1 flex items-center justify-between gap-4">
                              <span>{data.name}</span>
                              <span className={data.isForecast ? 'text-cyan-400 font-bold' : 'text-slate-300'}>
                                {data.isForecast ? 'Forecast Rollout' : 'Observed State'}
                              </span>
                            </div>
                            <div className="text-red-400 font-bold text-sm">
                              Attack Probability: {data.attackProb}%
                            </div>
                            <div className="text-slate-300 mt-0.5">
                              Stage: <span className="text-amber-400 font-semibold">{data.stage}</span>
                            </div>
                          </div>
                        );
                      }
                      return null;
                    }}
                  />
                  <ReferenceLine y={35} stroke="#eab308" strokeDasharray="4 4" label={{ value: 'Elevated (35%)', fill: '#eab308', fontSize: 10 }} />
                  <ReferenceLine y={65} stroke="#f97316" strokeDasharray="4 4" label={{ value: 'High (65%)', fill: '#f97316', fontSize: 10 }} />
                  <ReferenceLine y={85} stroke="#ef4444" strokeDasharray="4 4" label={{ value: 'Critical (85%)', fill: '#ef4444', fontSize: 10 }} />
                  <Area
                    type="monotone"
                    dataKey="attackProb"
                    stroke="#ef4444"
                    strokeWidth={2.5}
                    fillOpacity={1}
                    fill="url(#attackProbGrad)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          <div className="pt-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
            <span className="font-mono text-emerald-400">
              State history: {currentWindow + 1} observed windows ({((currentWindow + 1) * 10)} seconds)
            </span>
            <button
              onClick={() => onNavigateTab('forecasts')}
              className="text-cyan-400 hover:text-cyan-300 flex items-center space-x-1 font-mono"
            >
              <span>Explore K-Step Simulation Table</span>
              <ExternalLink className="w-3 h-3" />
            </button>
          </div>
        </div>

        {/* Forecast Horizon Panel (1 Col) */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-2.5">
              <h4 className="text-xs font-bold font-mono uppercase text-slate-300 tracking-wider">
                Predicted Forward Trajectory
              </h4>
              <span className="text-[10px] text-cyan-400 font-mono">T+1 to T+5</span>
            </div>
            <p className="text-xs text-slate-400 mb-3">
              Autoregressive state transition rollout P(S_t+k | S_t+k-1).
            </p>

            {/* Steps list */}
            <div className="space-y-2">
              {forecasts.slice(0, 5).map((f) => {
                const stageInfo = ATTACK_STAGE_INFO[f.predictedStage] || ATTACK_STAGE_INFO.BENIGN;
                return (
                  <div
                    key={f.step}
                    className="p-2 rounded-lg bg-slate-950/60 border border-slate-800 flex items-center justify-between text-xs font-mono"
                  >
                    <div className="flex items-center space-x-2">
                      <span className="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-400 font-bold text-[10px]">
                        T+{f.horizonSeconds}s
                      </span>
                      <span className="font-semibold text-slate-200" style={{ color: stageInfo.color }}>
                        {f.predictedStage.replace(/_/g, ' ')}
                      </span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span className="text-slate-400 font-mono text-[11px]">
                        {(f.attackProbability * 100).toFixed(0)}%
                      </span>
                      <span
                        className={`w-2 h-2 rounded-full ${
                          f.riskLevel === 'CRITICAL'
                            ? 'bg-red-500'
                            : f.riskLevel === 'HIGH'
                            ? 'bg-orange-500'
                            : f.riskLevel === 'ELEVATED'
                            ? 'bg-amber-500'
                            : 'bg-emerald-500'
                        }`}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400">Early Warning Advantage:</span>
              <span className="font-mono text-emerald-400 font-bold">
                {attackProbability > 0.35 ? '+140s lead time' : 'Monitoring'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Bottom Row: Top Driving Features (SHAP preview) & MITRE ATT&CK Quick Action Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Driving Network Signals (Explainability Preview) */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between mb-3">
            <div>
              <h4 className="text-xs font-bold font-mono uppercase text-slate-300 tracking-wider">
                Top Threat Drivers & Attribution (SHAP)
              </h4>
              <p className="text-xs text-slate-400 mt-0.5">
                Features driving the transition dynamics towards an infiltration state.
              </p>
            </div>
            <button
              onClick={() => onNavigateTab('explainability')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-mono flex items-center space-x-1"
            >
              <span>View Full SHAP</span>
              <ExternalLink className="w-3 h-3" />
            </button>
          </div>

          <div className="space-y-2">
            {attributions.slice(0, 4).map((attr) => (
              <div
                key={attr.featureName}
                className="p-2 rounded-lg bg-slate-950/60 border border-slate-800/80 flex items-center justify-between text-xs font-mono"
              >
                <div>
                  <div className="font-semibold text-slate-200">{attr.displayName}</div>
                  <div className="text-[10px] text-slate-400">
                    Observed: <span className="text-slate-300 font-bold">{attr.formattedValue}</span> &bull; Category: {attr.category}
                  </div>
                </div>
                <div className="text-right">
                  <span
                    className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold ${
                      attr.direction === 'RISK_INCREASE'
                        ? 'bg-red-950 text-red-400 border border-red-800/60'
                        : 'bg-emerald-950 text-emerald-400 border border-emerald-800/60'
                    }`}
                  >
                    {attr.direction === 'RISK_INCREASE' ? `+${(attr.contribution * 100).toFixed(0)}% Risk` : `${(attr.contribution * 100).toFixed(0)}% Benign`}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* MITRE ATT&CK Candidate Techniques & Decision Support */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between mb-3">
            <div>
              <h4 className="text-xs font-bold font-mono uppercase text-slate-300 tracking-wider">
                Candidate MITRE ATT&CK Techniques
              </h4>
              <p className="text-xs text-slate-400 mt-0.5">
                Evidence-grounded hypothesis mapping based on network telemetry signals.
              </p>
            </div>
            <button
              onClick={() => onNavigateTab('investigation')}
              className="text-xs text-cyan-400 hover:text-cyan-300 font-mono flex items-center space-x-1"
            >
              <span>Investigation Room</span>
              <ExternalLink className="w-3 h-3" />
            </button>
          </div>

          {mitreCandidates.length > 0 ? (
            <div className="space-y-2">
              {mitreCandidates.slice(0, 2).map((cand) => (
                <div
                  key={cand.id}
                  className="p-3 rounded-lg bg-slate-950/70 border border-slate-750 text-xs"
                >
                  <div className="flex items-center justify-between mb-1 font-mono">
                    <span className="font-bold text-amber-400">
                      {cand.id} - {cand.name}
                    </span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                      {(cand.confidence * 100).toFixed(0)}% Conf.
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400 mb-2">
                    <span className="font-semibold text-slate-300">Evidence: </span>
                    {cand.evidence[0]}
                  </div>
                  <div className="p-2 rounded bg-slate-900/90 border border-slate-800 text-[11px] text-emerald-300 font-mono flex items-start space-x-1.5">
                    <CheckCircle className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                    <span><strong className="text-slate-200">Recommended Action:</strong> {cand.recommendedAction}</span>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-6 rounded-lg bg-slate-950/40 border border-slate-800/80 text-center text-xs text-slate-500 font-mono">
              Network state matches Benign baseline. No malicious MITRE ATT&CK techniques identified.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
