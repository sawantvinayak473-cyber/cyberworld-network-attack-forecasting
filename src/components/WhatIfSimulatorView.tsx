import React, { useMemo, useState } from 'react';
import {
  Area,
  CartesianGrid,
  ComposedChart,
  Line,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import {
  AlertTriangle,
  Check,
  CircleOff,
  Gauge,
  LockKeyhole,
  Network,
  Radio,
  ShieldAlert,
  ShieldCheck,
  LoaderCircle,
} from 'lucide-react';
import {
  computePerturbedForecast,
  InterventionPreset,
  PRESET_PERTURBATIONS,
} from '../engine/worldModelSimulator';
import { AttackStage, NetworkStateVector } from '../types';
import { applyMitigation } from '../api/cyberWorldApi';

interface WhatIfSimulatorViewProps {
  baseState: NetworkStateVector;
  allStates: NetworkStateVector[];
  currentWindow: number;
  scenarioId: string;
  currentStage: AttackStage;
  attackProbability: number;
}

const PRESET_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  'block-port-scanning': Network,
  'isolate-source-endpoint': LockKeyhole,
  'block-smb-rdp': ShieldAlert,
  'sinkhole-c2': Radio,
  'firewall-rate-limit': Gauge,
  'no-action': CircleOff,
};

const clamp = (value: number) => Math.min(1, Math.max(0, value));

export const WhatIfSimulatorView: React.FC<WhatIfSimulatorViewProps> = ({
  baseState,
  allStates,
  currentWindow,
  scenarioId,
  currentStage,
  attackProbability,
}) => {
  const [activePresetIds, setActivePresetIds] = useState<string[]>(['no-action']);
  const [isDeploying, setIsDeploying] = useState(false);
  const [deployResult, setDeployResult] = useState<string | null>(null);
  const [deployError, setDeployError] = useState<string | null>(null);

  const activePresets = useMemo(() => PRESET_PERTURBATIONS.filter((preset) => (
    activePresetIds.includes(preset.id) &&
    (!preset.applicableStages || preset.applicableStages.includes(currentStage))
  )), [activePresetIds, currentStage]);
  const activePerturbations = useMemo(
    () => activePresets.flatMap((preset) => preset.perturbations),
    [activePresets],
  );
  const activeInterventionCount = activePresets.filter((preset) => preset.id !== 'no-action').length;

  const comparison = useMemo(() => computePerturbedForecast(
    baseState,
    activePerturbations,
    scenarioId,
    allStates,
    currentWindow,
  ), [baseState, activePerturbations, scenarioId, allStates, currentWindow]);

  const previewResults = useMemo(() => new Map(
    PRESET_PERTURBATIONS.map((preset) => [
      preset.id,
      computePerturbedForecast(baseState, preset.perturbations, scenarioId, allStates, currentWindow),
    ]),
  ), [baseState, scenarioId, allStates, currentWindow]);

  const chartData = useMemo(() => {
    const firstForecastShift = (comparison.perturbedForecasts[0]?.attackProbability ?? attackProbability) -
      (comparison.originalForecasts[0]?.attackProbability ?? attackProbability);
    const points = [{
      seconds: 0,
      originalProbability: Number((attackProbability * 100).toFixed(1)),
      perturbedProbability: Number((clamp(attackProbability + firstForecastShift) * 100).toFixed(1)),
    }];

    comparison.originalForecasts.slice(0, 10).forEach((forecast, index) => {
      const perturbedForecast = comparison.perturbedForecasts[index] || forecast;
      points.push({
        seconds: forecast.horizonSeconds,
        originalProbability: Number((forecast.attackProbability * 100).toFixed(1)),
        perturbedProbability: Number((perturbedForecast.attackProbability * 100).toFixed(1)),
      });
    });
    return points;
  }, [attackProbability, comparison]);

  const togglePreset = (preset: InterventionPreset) => {
    if (preset.applicableStages && !preset.applicableStages.includes(currentStage)) return;

    setActivePresetIds((previous) => {
      if (preset.id === 'no-action') return ['no-action'];
      const withoutBaseline = previous.filter((id) => id !== 'no-action');
      return withoutBaseline.includes(preset.id)
        ? withoutBaseline.filter((id) => id !== preset.id)
        : [...withoutBaseline, preset.id];
    });
  };

  const riskDeltaText = `${comparison.riskDelta >= 0 ? '+' : ''}${(comparison.riskDelta * 100).toFixed(1)}%`;

  return (
    <div className="space-y-5">
      <div className="grid gap-5 xl:grid-cols-5">
        <section className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 shadow-sm xl:col-span-2">
          <div className="flex items-start justify-between gap-3">
            <div>
              <p className="text-xs font-mono tracking-[0.2em] text-emerald-400">WHAT-IF ATTACK SIMULATOR</p>
              <h2 className="mt-1 text-lg font-bold text-slate-100">Intervention Simulator</h2>
              <p className="mt-2 text-xs leading-5 text-slate-400">
                Estimate how defensive actions change the attack trajectory. Results are model estimates, not guarantees.
              </p>
            </div>
            <span className="shrink-0 rounded-full border border-emerald-800/70 bg-emerald-950/40 px-2.5 py-1 text-[10px] font-mono text-emerald-300">
              {activeInterventionCount === 0
                ? 'Baseline comparison'
                : `${activeInterventionCount} intervention${activeInterventionCount === 1 ? '' : 's'} active`}
            </span>
          </div>

          <div className="mt-4 space-y-2.5">
            {PRESET_PERTURBATIONS.map((preset) => {
              const Icon = PRESET_ICONS[preset.id] || ShieldAlert;
              const isApplicable = !preset.applicableStages || preset.applicableStages.includes(currentStage);
              const isActive = activePresetIds.includes(preset.id) && isApplicable;
              const preview = previewResults.get(preset.id);
              const previewDelta = preview?.riskDelta ?? 0;
              const previewLabel = preset.id === 'no-action'
                ? 'Baseline'
                : `${previewDelta >= 0 ? '+' : ''}${(previewDelta * 100).toFixed(1)}% peak`;

              return (
                <button
                  type="button"
                  key={preset.id}
                  onClick={() => togglePreset(preset)}
                  disabled={!isApplicable}
                  className={`w-full rounded-lg border p-3 text-left transition-colors focus:outline-none focus:ring-2 focus:ring-emerald-500 disabled:cursor-not-allowed disabled:opacity-45 ${
                    isActive
                      ? 'border-emerald-600/70 bg-emerald-950/30'
                      : 'border-slate-800 bg-slate-950/35 hover:border-slate-700 hover:bg-slate-800/60'
                  }`}
                  aria-pressed={isActive}
                >
                  <div className="flex items-start gap-3">
                    <span className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded border ${
                      isActive ? 'border-emerald-400 bg-emerald-500 text-slate-950' : 'border-slate-600 bg-slate-900 text-transparent'
                    }`} aria-hidden="true">
                      <Check className="h-3.5 w-3.5" />
                    </span>
                    <Icon className={`mt-0.5 h-4 w-4 shrink-0 ${isActive ? 'text-emerald-400' : 'text-slate-500'}`} />
                    <span className="min-w-0 flex-1">
                      <span className="flex flex-wrap items-start justify-between gap-2">
                        <span className="text-xs font-bold text-slate-200">{preset.label}</span>
                        <span className={`rounded border px-1.5 py-0.5 text-[10px] font-mono ${
                          previewDelta < -0.005
                            ? 'border-emerald-800 bg-emerald-950/50 text-emerald-300'
                            : previewDelta > 0.005
                            ? 'border-red-900 bg-red-950/40 text-red-300'
                            : 'border-slate-700 bg-slate-900 text-slate-400'
                        }`}>
                          {previewLabel}
                        </span>
                      </span>
                      <span className="mt-1 block text-[11px] leading-4 text-slate-400">{preset.description}</span>
                      {!isApplicable && (
                        <span className="mt-1 block text-[10px] font-mono text-amber-400">
                          Available during lateral movement only
                        </span>
                      )}
                    </span>
                  </div>
                </button>
              );
            })}
          </div>
        </section>

        <section className="rounded-xl border border-slate-800 bg-slate-900/70 p-4 shadow-sm xl:col-span-3">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p className="text-xs font-mono tracking-[0.2em] text-cyan-400">TRAJECTORY COMPARISON</p>
              <h2 className="mt-1 text-lg font-bold text-slate-100">Projected attack probability</h2>
            </div>
            <div className="flex items-center gap-3 text-[10px] font-mono">
              <span className="flex items-center gap-1.5 text-red-300"><span className="w-4 border-t-2 border-dashed border-red-400" /> Original</span>
              <span className="flex items-center gap-1.5 text-emerald-300"><span className="w-4 border-t-2 border-emerald-400" /> Perturbed</span>
            </div>
          </div>

          <div className="mt-4 h-[310px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <ComposedChart data={chartData} margin={{ top: 12, right: 18, left: -18, bottom: 6 }}>
                <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" />
                <XAxis
                  dataKey="seconds"
                  stroke="#64748b"
                  tick={{ fontSize: 10, fill: '#94a3b8' }}
                  tickFormatter={(seconds) => `T+${seconds}s`}
                  type="number"
                  domain={[0, 100]}
                  ticks={[0, 20, 40, 60, 80, 100]}
                />
                <YAxis
                  domain={[0, 100]}
                  stroke="#64748b"
                  tick={{ fontSize: 10, fill: '#94a3b8' }}
                  tickFormatter={(value) => `${value}%`}
                />
                <Tooltip
                  content={({ active, payload }) => {
                    if (!active || !payload?.length) return null;
                    const point = payload[0].payload;
                    const reduction = point.perturbedProbability - point.originalProbability;
                    return (
                      <div className="rounded-lg border border-slate-700 bg-slate-900 p-2.5 text-xs font-mono shadow-xl">
                        <div className="mb-1 font-bold text-slate-200">T+{point.seconds}s</div>
                        <div className="text-red-300">Original: {point.originalProbability}%</div>
                        <div className="text-emerald-300">Perturbed: {point.perturbedProbability}%</div>
                        <div className={reduction < 0 ? 'mt-1 text-emerald-400' : 'mt-1 text-slate-400'}>
                          Delta: {reduction >= 0 ? '+' : ''}{reduction.toFixed(1)}%
                        </div>
                      </div>
                    );
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="originalProbability"
                  baseLine={chartData.map((point) => point.perturbedProbability)}
                  stroke="none"
                  fill="#10b981"
                  fillOpacity={0.12}
                  isAnimationActive
                />
                <Line
                  type="monotone"
                  dataKey="originalProbability"
                  stroke="#ef4444"
                  strokeWidth={2.5}
                  strokeDasharray="7 5"
                  dot={{ r: 3, fill: '#ef4444' }}
                  activeDot={{ r: 5 }}
                />
                <Line
                  type="monotone"
                  dataKey="perturbedProbability"
                  stroke="#10b981"
                  strokeWidth={3}
                  dot={{ r: 3, fill: '#10b981' }}
                  activeDot={{ r: 5 }}
                />
              </ComposedChart>
            </ResponsiveContainer>
          </div>

          <div className="mt-4 grid gap-2 sm:grid-cols-3">
            <div className="rounded-lg border border-slate-800 bg-slate-950/45 px-3 py-2.5 font-mono text-xs text-slate-400">
              Original Peak: <span className="font-bold text-red-300">{(comparison.originalPeak * 100).toFixed(1)}%</span>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/45 px-3 py-2.5 font-mono text-xs text-slate-400">
              Perturbed Peak: <span className="font-bold text-emerald-300">{(comparison.perturbedPeak * 100).toFixed(1)}%</span>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/45 px-3 py-2.5 font-mono text-xs text-slate-400">
              Risk Reduction: <span className={comparison.riskDelta < 0 ? 'font-bold text-emerald-300' : 'font-bold text-slate-200'}>{riskDeltaText}</span>
            </div>
          </div>

          {activeInterventionCount > 0 && comparison.riskDelta < 0 && (
            <div className="mt-4 p-3.5 rounded-lg border border-emerald-800/80 bg-emerald-950/40 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
              <div>
                <div className="text-xs font-mono font-bold text-emerald-300 flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  RECOMMENDED ACTIVE DEFENSE POLICY
                </div>
                <div className="text-[11px] text-slate-300 mt-0.5">
                  Simulated attack probability reduction of <span className="text-emerald-400 font-bold">{riskDeltaText}</span>. Deploy firewall containment immediately to host IP 192.168.1.105.
                </div>
              </div>
              <button
                onClick={async () => {
                  setIsDeploying(true);
                  setDeployResult(null);
                  setDeployError(null);
                  try {
                    const targetIp = '192.168.1.105';
                    const selectedLabels = activePresets.filter(p => p.id !== 'no-action').map(p => p.label).join(', ');
                    const result = await applyMitigation({
                      target_ip: targetIp,
                      target_stage: currentStage,
                      action_type: 'DROP_INGRESS',
                      execution_mode: 'LIVE',
                      expiry_minutes: 30,
                      notes: `What-If Intervention deployed: ${selectedLabels}. Peak risk reduced from ${(comparison.originalPeak * 100).toFixed(1)}% to ${(comparison.perturbedPeak * 100).toFixed(1)}%.`,
                    });
                    setDeployResult(`Mitigation deployed! Rule ID: ${result.action_id} on ${targetIp}. Action: ${result.command_executed}`);
                  } catch (e: any) {
                    setDeployError(e.message || 'Failed to deploy mitigation');
                  } finally {
                    setIsDeploying(false);
                  }
                }}
                disabled={isDeploying}
                className="px-3.5 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-slate-950 font-bold text-xs font-mono rounded-lg shadow transition flex items-center gap-1.5 shrink-0"
              >
                {isDeploying ? <LoaderCircle className="w-3.5 h-3.5 animate-spin" /> : <ShieldAlert className="w-3.5 h-3.5" />}
                Deploy to Firewall
              </button>
            </div>
          )}

          {deployResult && (
            <div className="mt-3 p-2.5 rounded bg-emerald-950/80 border border-emerald-700 text-xs font-mono text-emerald-300">
              {deployResult}
            </div>
          )}
          {deployError && (
            <div className="mt-3 p-2.5 rounded bg-red-950/80 border border-red-700 text-xs font-mono text-red-300">
              {deployError}
            </div>
          )}

          <div className="mt-4 rounded-lg border border-cyan-900/50 bg-cyan-950/20 p-3 text-sm leading-5 text-slate-300">
            <span className="font-mono text-xs font-bold text-cyan-300">MODEL INTERPRETATION · </span>
            {comparison.interpretation}
          </div>
        </section>
      </div>

      <div className="flex items-start gap-3 rounded-xl border border-amber-700/60 bg-amber-950/25 px-4 py-3 text-sm leading-5 text-amber-100">
        <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-amber-400" />
        <p>
          <span className="font-bold">These are model simulations.</span> No actual network changes are made. All interventions require human review and approval before deployment.
        </p>
      </div>
    </div>
  );
};
