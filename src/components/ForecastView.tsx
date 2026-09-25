import React, { useMemo } from 'react';
import {
  Area,
  Bar,
  ComposedChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from 'recharts';
import {
  Clock,
  Info,
} from 'lucide-react';
import { ForecastStep, AttackStage, NetworkStateVector } from '../types';
import { ATTACK_STAGE_INFO } from '../mockData/scenarios';
import { computeCalibrationData, computeConfidenceBounds } from '../engine/worldModelSimulator';

interface ForecastViewProps {
  forecasts: ForecastStep[];
  currentWindow: number;
  currentState: NetworkStateVector;
  currentStage: AttackStage;
  predictedNextStage: AttackStage;
  attackProbability: number;
  earlyWarningLeadTimeSec: number;
}

export const ForecastView: React.FC<ForecastViewProps> = ({
  forecasts,
  currentWindow,
  currentState,
  currentStage,
  predictedNextStage,
  attackProbability,
  earlyWarningLeadTimeSec,
}) => {
  const currentConfidenceBounds = computeConfidenceBounds(attackProbability, 0.95);

  // Chart data covering T+0 to T+10
  const chartData = [
    {
      step: 'T+0s (Now)',
      seconds: 0,
      prob: Number((attackProbability * 100).toFixed(1)),
      upperConfidence: Number((currentConfidenceBounds.upperConfidenceBound * 100).toFixed(1)),
      lowerConfidence: Number((currentConfidenceBounds.lowerConfidenceBound * 100).toFixed(1)),
      confidenceBase: Number((currentConfidenceBounds.lowerConfidenceBound * 100).toFixed(1)),
      confidenceBand: Number(((currentConfidenceBounds.upperConfidenceBound - currentConfidenceBounds.lowerConfidenceBound) * 100).toFixed(1)),
      stage: currentStage,
    },
    ...forecasts.map((f) => ({
      step: `T+${f.horizonSeconds}s`,
      seconds: f.horizonSeconds,
      prob: Number((f.attackProbability * 100).toFixed(1)),
      upperConfidence: Number((f.upperConfidenceBound * 100).toFixed(1)),
      lowerConfidence: Number((f.lowerConfidenceBound * 100).toFixed(1)),
      confidenceBase: Number((f.lowerConfidenceBound * 100).toFixed(1)),
      confidenceBand: Number(((f.upperConfidenceBound - f.lowerConfidenceBound) * 100).toFixed(1)),
      stage: f.predictedStage,
    })),
  ];

  const { calibrationData, ece } = useMemo(() => {
    const buckets = computeCalibrationData();
    const ece = buckets.length > 0
      ? buckets.reduce((total, bucket) => total + bucket.calibrationError, 0) / buckets.length
      : 0;

    return {
      calibrationData: buckets.map((bucket) => ({
        ...bucket,
        empiricalPercent: Number((bucket.empiricalFrequency * 100).toFixed(1)),
        perfectCalibrationPercent: Number((bucket.predictedMidpoint * 100).toFixed(1)),
      })),
      ece,
    };
  }, []);

  const calibrationAssessment = ece < 0.05
    ? { label: 'Well Calibrated', className: 'text-emerald-400 border-emerald-800 bg-emerald-950/40' }
    : ece <= 0.1
    ? { label: 'Moderate Calibration', className: 'text-amber-400 border-amber-800 bg-amber-950/40' }
    : { label: 'Needs Recalibration', className: 'text-red-400 border-red-800 bg-red-950/40' };

  return (
    <div className="space-y-5">
      {/* Top Banner: World Model Forward Simulation Theory */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2">
              <Clock className="w-5 h-5 text-cyan-400" />
              <h3 className="text-sm font-bold font-mono text-slate-100">
                MULTI-STEP INFILTRATION FORWARD SIMULATION
              </h3>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-3xl">
              Rather than scoring a single static flow, the CyberWorld World Model computes autoregressive forward transitions:
              <code className="text-cyan-300 font-mono ml-1 px-1.5 py-0.5 bg-slate-950 rounded border border-slate-800">
                {'P(S_t+1 | S_t) \u2192 P(S_t+2 | S_t+1) \u2192 ... \u2192 P(S_t+10 | S_t+9)'}
              </code>
              . This exposes whether subtle early reconnaissance or slow port sweeps inevitably converge toward an active compromise.
            </p>
          </div>

          <div className="flex items-center space-x-3">
            <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-800/60 font-mono text-xs">
              <div className="text-emerald-400 font-bold text-base">+{earlyWarningLeadTimeSec}s</div>
              <div className="text-slate-400 text-[10px]">Early Warning Lead Time</div>
            </div>
          </div>
        </div>
      </div>

      {/* Trajectory Probability Curve */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="flex items-center justify-between mb-2">
          <div>
            <h4 className="text-xs font-bold font-mono uppercase text-slate-300 tracking-wider">
              10-Step Infiltration Probability Horizon (T+10s to T+100s)
            </h4>
            <p className="text-xs text-slate-400">
              Confidence interval expands as simulation horizon increases into the future.
            </p>
          </div>
          <div className="flex items-center space-x-3 text-xs font-mono">
            <span className="flex items-center space-x-1 text-cyan-400">
              <span className="w-2.5 h-1 bg-cyan-400" />
              <span>Projected Probability</span>
            </span>
            <span className="flex items-center space-x-1 text-emerald-300">
              <span className="w-2.5 h-2.5 rounded-sm bg-emerald-500/30 border border-emerald-500/50" />
              <span>95% Confidence Band</span>
            </span>
          </div>
        </div>

        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <ComposedChart data={chartData} margin={{ top: 15, right: 15, left: -20, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="step" stroke="#64748b" tick={{ fontSize: 10, fill: '#94a3b8' }} />
              <YAxis domain={[0, 100]} stroke="#64748b" tick={{ fontSize: 10, fill: '#94a3b8' }} unit="%" />
              <Tooltip
                content={({ active, payload }) => {
                  if (active && payload && payload.length) {
                    const data = payload[0].payload;
                    return (
                      <div className="bg-slate-900 border border-slate-700 p-2.5 rounded-lg shadow-xl text-xs font-mono">
                        <div className="text-slate-300 font-bold mb-1">{data.step}</div>
                        <div className="text-cyan-400 font-bold">Attack Probability: {data.prob}%</div>
                        <div className="text-slate-400">
                          Uncertainty: [{data.lowerConfidence}% - {data.upperConfidence}%]
                        </div>
                        <div className="text-amber-400 mt-1">Predicted Stage: {data.stage}</div>
                      </div>
                    );
                  }
                  return null;
                }}
              />
              <ReferenceLine y={35} stroke="#eab308" strokeDasharray="3 3" />
              <ReferenceLine y={65} stroke="#f97316" strokeDasharray="3 3" />
              <ReferenceLine y={85} stroke="#ef4444" strokeDasharray="3 3" />
              <Area
                type="monotone"
                dataKey="confidenceBase"
                stackId="confidence-band"
                stroke="none"
                fill="transparent"
                fillOpacity={0}
                legendType="none"
              />
              <Area
                type="monotone"
                dataKey="confidenceBand"
                stackId="confidence-band"
                name="95% Confidence Band"
                stroke="none"
                fill="rgba(16, 185, 129, 0.1)"
                legendType="rect"
              />
              <Line
                type="monotone"
                dataKey="prob"
                stroke="#38bdf8"
                strokeWidth={3}
                dot={{ r: 4, fill: '#38bdf8' }}
                activeDot={{ r: 6 }}
              />
            </ComposedChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Model Calibration */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between mb-4">
          <div>
            <h4 className="text-xs font-bold font-mono uppercase text-slate-300 tracking-wider">
              Model Calibration
            </h4>
            <p className="text-xs text-slate-400 mt-1">
              Observed attack rate for predictions grouped by their probability bucket across all five scenarios.
            </p>
          </div>
          <div className="flex items-center gap-2 font-mono text-xs">
            <span className="text-slate-400">ECE</span>
            <span className="text-slate-100 font-bold">{(ece * 100).toFixed(1)}%</span>
            <span className={`px-2 py-1 rounded border font-bold ${calibrationAssessment.className}`}>
              {calibrationAssessment.label}
            </span>
          </div>
        </div>

        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <ComposedChart data={calibrationData} margin={{ top: 15, right: 15, left: -20, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis
                dataKey="bucketLabel"
                interval={0}
                stroke="#64748b"
                tick={{ fontSize: 10, fill: '#94a3b8' }}
              />
              <YAxis
                domain={[0, 100]}
                stroke="#64748b"
                tick={{ fontSize: 10, fill: '#94a3b8' }}
                unit="%"
              />
              <Tooltip
                content={({ active, payload }) => {
                  if (active && payload && payload.length) {
                    const data = payload[0].payload;
                    return (
                      <div className="bg-slate-900 border border-slate-700 p-2.5 rounded-lg shadow-xl text-xs font-mono">
                        <div className="text-slate-300 font-bold mb-1">{data.bucketLabel}</div>
                        <div className="text-emerald-400">Empirical frequency: {data.empiricalPercent}%</div>
                        <div className="text-red-400">Perfect calibration: {data.perfectCalibrationPercent}%</div>
                        <div className="text-slate-400 mt-1">Samples: {data.sampleCount}</div>
                      </div>
                    );
                  }
                  return null;
                }}
              />
              <Bar
                dataKey="empiricalPercent"
                name="Empirical frequency"
                fill="#10b981"
                fillOpacity={0.75}
                radius={[3, 3, 0, 0]}
              />
              <Line
                type="linear"
                dataKey="perfectCalibrationPercent"
                name="Perfect calibration"
                stroke="#ef4444"
                strokeWidth={2}
                strokeDasharray="6 4"
                dot={false}
              />
            </ComposedChart>
          </ResponsiveContainer>
        </div>

        <div className="mt-3 flex items-start gap-2 rounded-lg border border-slate-800 bg-slate-950/50 p-3 text-xs text-slate-400">
          <Info className="mt-0.5 h-4 w-4 shrink-0 text-cyan-400" />
          <p>
            A well-calibrated model means that when it says 70% probability, approximately 70% of those predictions correspond to actual attacks in the training set.
          </p>
        </div>
      </div>

      {/* Detailed Forward Rollout Table */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
        <h4 className="text-xs font-bold font-mono uppercase text-slate-300 tracking-wider mb-3">
          Autoregressive State Transition Matrix (T+1 to T+10)
        </h4>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 bg-slate-950/50">
                <th className="py-2.5 px-3">Horizon</th>
                <th className="py-2.5 px-3">Attack Likelihood P(A)</th>
                <th className="py-2.5 px-3">Predicted Attack Stage</th>
                <th className="py-2.5 px-3">Confidence</th>
                <th className="py-2.5 px-3">Risk Tier</th>
                <th className="py-2.5 px-3">Predicted State & Signals</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {forecasts.map((f) => {
                const stageInfo = ATTACK_STAGE_INFO[f.predictedStage] || ATTACK_STAGE_INFO.BENIGN;
                return (
                  <tr key={f.step} className="hover:bg-slate-850/40 transition-colors">
                    <td className="py-2.5 px-3 font-bold text-cyan-400">
                      T+{f.horizonSeconds}s ({f.step} step)
                    </td>
                    <td className="py-2.5 px-3">
                      <div className="flex items-center space-x-2">
                        <span className="font-extrabold text-slate-100">
                          {(f.attackProbability * 100).toFixed(1)}%
                        </span>
                        <div className="w-16 bg-slate-800 h-1.5 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${
                              f.attackProbability > 0.85
                                ? 'bg-red-500'
                                : f.attackProbability > 0.65
                                ? 'bg-orange-500'
                                : f.attackProbability > 0.35
                                ? 'bg-amber-500'
                                : 'bg-emerald-500'
                            }`}
                            style={{ width: `${f.attackProbability * 100}%` }}
                          />
                        </div>
                      </div>
                    </td>
                    <td className="py-2.5 px-3 font-semibold" style={{ color: stageInfo.color }}>
                      {f.predictedStage.replace(/_/g, ' ')}
                    </td>
                    <td className="py-2.5 px-3 text-slate-300">
                      {(f.confidence * 100).toFixed(0)}%
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          f.riskLevel === 'CRITICAL'
                            ? 'bg-red-950 text-red-400 border border-red-800'
                            : f.riskLevel === 'HIGH'
                            ? 'bg-orange-950 text-orange-400 border border-orange-800'
                            : f.riskLevel === 'ELEVATED'
                            ? 'bg-amber-950 text-amber-400 border border-amber-800'
                            : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                        }`}
                      >
                        {f.riskLevel}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                      SYN/ACK ~{f.predictedStateSummary.synAckRatio}x &bull; Port Div ~{(f.predictedStateSummary.portDiversity * 100).toFixed(0)}% &bull; Burstiness ~{f.predictedStateSummary.burstiness}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
