import React, { useMemo } from 'react';
import { Alert, AttackStage, ForecastStep } from '../types';
import { ATTACK_STAGE_INFO } from '../mockData/scenarios';

interface IncidentTimelineViewProps {
  alertsState: Alert[];
  forecasts: ForecastStep[];
  currentWindow: number;
  totalWindows: number;
  predictedCurrentStage: AttackStage;
  onSelectAlertForInvestigation: (alert: Alert) => void;
}

const STAGES: AttackStage[] = [
  'BENIGN',
  'RECONNAISSANCE',
  'INITIAL_ACCESS',
  'LATERAL_MOVEMENT',
  'COMMAND_AND_CONTROL',
  'EXFILTRATION',
];

function severityStyle(severity: Alert['severity']) {
  switch (severity) {
    case 'CRITICAL':
      return { dot: 'w-5 h-5', chip: 'border-red-500/50 bg-red-950/50 text-red-300' };
    case 'HIGH':
      return { dot: 'w-4 h-4', chip: 'border-orange-500/50 bg-orange-950/50 text-orange-300' };
    case 'MEDIUM':
      return { dot: 'w-3 h-3', chip: 'border-amber-500/50 bg-amber-950/50 text-amber-300' };
    default:
      return { dot: 'w-2.5 h-2.5', chip: 'border-slate-600 bg-slate-800 text-slate-300' };
  }
}

export const IncidentTimelineView: React.FC<IncidentTimelineViewProps> = ({
  alertsState,
  forecasts,
  currentWindow,
  totalWindows,
  predictedCurrentStage,
  onSelectAlertForInvestigation,
}) => {
  const sortedAlerts = useMemo(
    () => [...alertsState].sort((a, b) => a.timeOffsetSeconds - b.timeOffsetSeconds),
    [alertsState],
  );
  const progress = Math.min(100, ((currentWindow + 1) / Math.max(1, totalWindows)) * 100);

  return (
    <section className="rounded-xl border border-slate-800 bg-slate-900/55 p-4 sm:p-5 shadow-sm">
      <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-xs font-mono tracking-[0.2em] text-cyan-400">INCIDENT TIMELINE</p>
          <h2 className="mt-1 text-lg font-bold text-slate-100">Observed alerts and projected escalation</h2>
        </div>
        <div className="font-mono text-xs text-slate-400">
          Window <span className="font-bold text-emerald-400">{currentWindow + 1}/{totalWindows}</span>
        </div>
      </div>

      <div className="mb-6">
        <div className="mb-2 flex items-center justify-between text-[11px] font-mono text-slate-400">
          <span>Scenario progression</span>
          <span>{progress.toFixed(0)}% replayed · {predictedCurrentStage.replace(/_/g, ' ')}</span>
        </div>
        <div className="relative h-3 overflow-hidden rounded-full bg-slate-800">
          <div className="absolute inset-0 flex">
            {STAGES.map((stage) => (
              <span
                key={stage}
                className="h-full"
                style={{ width: `${100 / STAGES.length}%`, backgroundColor: ATTACK_STAGE_INFO[stage].color, opacity: 0.38 }}
              />
            ))}
          </div>
          <div className="absolute inset-y-0 left-0 border-r-2 border-slate-100/90" style={{ width: `${progress}%` }} />
        </div>
        <div className="mt-1.5 grid grid-cols-3 gap-x-2 text-[9px] font-mono text-slate-500 sm:grid-cols-6">
          {STAGES.map((stage) => (
            <span key={stage} className="truncate">{stage.replace(/_/g, ' ')}</span>
          ))}
        </div>
      </div>

      <div className="max-h-[500px] overflow-y-auto pr-1">
        {sortedAlerts.length > 0 ? (
          <div className="relative pl-8">
            <div className="absolute bottom-3 left-[9px] top-3 w-px bg-slate-700" />
            {sortedAlerts.map((alert, index) => {
              const stageInfo = ATTACK_STAGE_INFO[alert.currentStage] || ATTACK_STAGE_INFO.BENIGN;
              const severity = severityStyle(alert.severity);
              const previousAlert = sortedAlerts[index - 1];
              const gap = previousAlert ? Math.max(0, alert.timeOffsetSeconds - previousAlert.timeOffsetSeconds) : 0;
              const isPrediction = alert.currentStage === 'BENIGN' && alert.predictedNextStage !== 'BENIGN';
              const title = isPrediction
                ? `${alert.predictedNextStage.replace(/_/g, ' ')} Predicted`
                : `${alert.currentStage.replace(/_/g, ' ')} Detected`;
              const topFeature = alert.topContributingFeatures[0];

              return (
                <React.Fragment key={alert.id}>
                  {previousAlert && (
                    <div className="relative my-3 h-4 text-[10px] font-mono text-slate-500">
                      <span className="absolute -left-8 top-0 w-5 text-center text-slate-600">⋮</span>
                      +{gap}s gap
                    </div>
                  )}
                  <div className="relative">
                    <span
                      className={`absolute -left-[29px] top-5 rounded-full ring-4 ring-[#090d16] ${severity.dot}`}
                      style={{ backgroundColor: stageInfo.color }}
                      aria-hidden="true"
                    />
                    <button
                      type="button"
                      onClick={() => onSelectAlertForInvestigation(alert)}
                      className="w-full border-l-4 border-slate-700 bg-slate-950/45 px-4 py-3 text-left transition-colors hover:bg-slate-800/70 focus:outline-none focus:ring-2 focus:ring-emerald-500/70"
                      style={{ borderLeftColor: stageInfo.color }}
                      aria-label={`Open investigation for ${title} at ${alert.timeOffsetSeconds} seconds`}
                    >
                      <div className="flex flex-wrap items-start justify-between gap-2">
                        <div>
                          <div className="font-mono text-[11px] text-cyan-300">+{alert.timeOffsetSeconds}s</div>
                          <h3 className="mt-0.5 text-sm font-bold" style={{ color: stageInfo.color }}>{title}</h3>
                        </div>
                        <span className={`rounded border px-2 py-0.5 text-[10px] font-mono font-bold ${severity.chip}`}>
                          {alert.severity}
                        </span>
                      </div>
                      <div className="mt-2 grid gap-1 text-[11px] text-slate-400 sm:grid-cols-3">
                        <span className="font-mono text-slate-300">{alert.sourceIp} <span className="text-slate-600">→</span> {alert.destinationIp}</span>
                        <span>Attack probability <span className="font-mono font-bold text-slate-200">{(alert.attackProbability * 100).toFixed(1)}%</span></span>
                        <span className="truncate">Top signal <span className="text-slate-200">{topFeature?.displayName || 'No feature attribution'}</span></span>
                      </div>
                    </button>
                  </div>
                </React.Fragment>
              );
            })}
          </div>
        ) : (
          <div className="py-10 text-center font-mono text-sm text-slate-500">
            No alerts have crossed the configured threshold in this replay window.
          </div>
        )}
      </div>

      <div className="mt-6 border-t border-slate-800 pt-4">
        <div className="mb-3 flex items-center justify-between">
          <h3 className="text-sm font-bold text-slate-200">Predicted</h3>
          <span className="font-mono text-[10px] text-slate-500">Next three rollout windows</span>
        </div>
        <div className="grid gap-3 md:grid-cols-3">
          {forecasts.slice(0, 3).map((forecast) => {
            const stageInfo = ATTACK_STAGE_INFO[forecast.predictedStage] || ATTACK_STAGE_INFO.BENIGN;
            return (
              <div
                key={forecast.step}
                className="border border-dashed border-slate-600 bg-slate-950/35 p-3"
                style={{ borderLeftColor: stageInfo.color, borderLeftWidth: 3 }}
              >
                <div className="font-mono text-[10px] text-slate-500">T+{forecast.horizonSeconds}s (Predicted)</div>
                <div className="mt-1 text-sm font-bold" style={{ color: stageInfo.color }}>
                  {forecast.predictedStage.replace(/_/g, ' ')}
                </div>
                <div className="mt-1 font-mono text-xs text-slate-300">
                  {(forecast.attackProbability * 100).toFixed(1)}% · {forecast.confidence.toFixed(2)} confidence
                </div>
              </div>
            );
          })}
          {forecasts.length === 0 && (
            <div className="border border-dashed border-slate-700 px-3 py-5 text-center font-mono text-xs text-slate-500 md:col-span-3">
              Forecast rollout is unavailable for this state.
            </div>
          )}
        </div>
      </div>
    </section>
  );
};
