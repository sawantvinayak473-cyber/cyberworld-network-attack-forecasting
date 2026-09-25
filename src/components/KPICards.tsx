import React from 'react';
import {
  ArrowRight,
  AlertOctagon,
  Radar,
  Hourglass,
  Zap,
} from 'lucide-react';
import { AttackStage } from '../types';
import type { ResidualAnomalyResult } from '../engine/worldModelSimulator';
import { ATTACK_STAGE_INFO } from '../mockData/scenarios';

interface KPICardsProps {
  attackProbability: number;
  currentStage: AttackStage;
  predictedNextStage: AttackStage;
  forecastHorizonSec: number;
  earlyWarningLeadTimeSec: number;
  activeAlertCount: number;
  residualAnomaly: ResidualAnomalyResult;
  ewes: {
    ewesScore: number;
    escalationRate: number;
    timeToCriticalSec: number;
    peakForecastProbability: number;
    escalationLabel: 'STABLE' | 'ESCALATING' | 'RAPIDLY_ESCALATING';
  };
}

const gaugePoint = (value: number) => {
  const angle = Math.PI - (Math.min(100, Math.max(0, value)) / 100) * Math.PI;
  return {
    x: 70 + 50 * Math.cos(angle),
    y: 80 - 50 * Math.sin(angle),
  };
};

const gaugeArc = (start: number, end: number) => {
  const startPoint = gaugePoint(start);
  const endPoint = gaugePoint(end);
  return `M ${startPoint.x} ${startPoint.y} A 50 50 0 0 1 ${endPoint.x} ${endPoint.y}`;
};

export const KPICards: React.FC<KPICardsProps> = ({
  attackProbability,
  currentStage,
  predictedNextStage,
  forecastHorizonSec,
  earlyWarningLeadTimeSec,
  activeAlertCount,
  residualAnomaly,
  ewes,
}) => {
  const currentInfo = ATTACK_STAGE_INFO[currentStage] || ATTACK_STAGE_INFO.BENIGN;
  const nextInfo = ATTACK_STAGE_INFO[predictedNextStage] || ATTACK_STAGE_INFO.BENIGN;
  const needleRotation = -90 + ewes.ewesScore * 1.8;
  const escalationColor = ewes.escalationLabel === 'RAPIDLY_ESCALATING'
    ? 'text-red-400'
    : ewes.escalationLabel === 'ESCALATING'
    ? 'text-amber-400'
    : 'text-emerald-400';
  const escalationText = `${ewes.escalationRate >= 0 ? '+' : ''}${ewes.escalationRate.toFixed(1)}%/window`;
  const timeToCriticalText = Number.isFinite(ewes.timeToCriticalSec)
    ? `${ewes.timeToCriticalSec}s`
    : '—';
  const topResidualFeature = residualAnomaly.surprisedFeatures[0];
  const residualLabel = residualAnomaly.anomalyType.replace(/_/g, ' ');

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-7 gap-3 mb-5">
      {/* 1. Early Warning Escalation Score */}
      <div className="rounded-xl p-3 border border-slate-700 bg-slate-900/80 backdrop-blur shadow-sm">
        <div className="flex items-center justify-between text-xs font-mono text-slate-400">
          <span>EARLY WARNING SCORE</span>
          <span className={`text-[9px] font-bold ${escalationColor}`}>{ewes.escalationLabel.replace(/_/g, ' ')}</span>
        </div>
        <svg viewBox="0 0 140 98" className="mx-auto mt-1 h-[86px] w-full max-w-[170px]" role="img" aria-label={`EWES score ${ewes.ewesScore} out of 100`}>
          <path d={gaugeArc(0, 35)} fill="none" stroke="#10b981" strokeWidth="10" strokeLinecap="round" opacity="0.8" />
          <path d={gaugeArc(35, 65)} fill="none" stroke="#f59e0b" strokeWidth="10" strokeLinecap="butt" opacity="0.8" />
          <path d={gaugeArc(65, 100)} fill="none" stroke="#ef4444" strokeWidth="10" strokeLinecap="round" opacity="0.8" />
          <g
            style={{
              transform: `rotate(${needleRotation}deg)`,
              transformOrigin: '70px 80px',
              transition: 'transform 500ms cubic-bezier(0.22, 1, 0.36, 1)',
            }}
          >
            <line x1="70" y1="80" x2="70" y2="36" stroke="#e2e8f0" strokeWidth="2.5" strokeLinecap="round" />
          </g>
          <circle cx="70" cy="80" r="4.5" fill="#e2e8f0" />
          <text x="70" y="67" textAnchor="middle" fill="#f8fafc" fontSize="21" fontWeight="800" fontFamily="ui-monospace, monospace">
            {ewes.ewesScore.toFixed(0)}
          </text>
          <text x="70" y="93" textAnchor="middle" fill="#94a3b8" fontSize="9" fontWeight="700" fontFamily="ui-monospace, monospace">
            EWES
          </text>
        </svg>
        <div className="mt-1 text-center text-[10px] leading-4 font-mono text-slate-400">
          <span>Escalation: <span className={escalationColor}>{escalationText}</span></span>
          <span className="text-slate-600"> · </span>
          <span>Time-to-Critical: {timeToCriticalText}</span>
          <span className="text-slate-600"> · </span>
          <span>Peak: {(ewes.peakForecastProbability * 100).toFixed(0)}%</span>
        </div>
      </div>

      {/* 2. Attack Probability Head */}
      <div className="rounded-xl p-3.5 border border-slate-800 bg-slate-900/60 backdrop-blur shadow-sm">
        <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-1.5">
          <span>ATTACK PROBABILITY</span>
          <Radar className="w-3.5 h-3.5 text-cyan-400" />
        </div>
        <div className="flex items-baseline space-x-1">
          <span className="text-2xl font-extrabold font-mono text-slate-100">
            {(attackProbability * 100).toFixed(1)}
          </span>
          <span className="text-xs font-mono text-slate-400">%</span>
        </div>
        <div className="w-full bg-slate-800 h-1.5 rounded-full mt-2 overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-300 ${
              attackProbability > 0.85
                ? 'bg-red-500'
                : attackProbability > 0.65
                ? 'bg-orange-500'
                : attackProbability > 0.35
                ? 'bg-amber-500'
                : 'bg-emerald-500'
            }`}
            style={{ width: `${Math.min(100, Math.max(5, attackProbability * 100))}%` }}
          />
        </div>
      </div>

      {/* 3. Current Inferred Stage */}
      <div className="rounded-xl p-3.5 border border-slate-800 bg-slate-900/60 backdrop-blur shadow-sm">
        <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-1.5">
          <span>CURRENT STAGE</span>
          <span
            className="w-2 h-2 rounded-full"
            style={{ backgroundColor: currentInfo.color }}
          />
        </div>
        <div
          className="text-sm font-bold font-mono truncate"
          style={{ color: currentInfo.color }}
          title={currentInfo.label}
        >
          {currentStage.replace(/_/g, ' ')}
        </div>
        <div className="text-[11px] text-slate-400 mt-1 truncate">
          {currentInfo.label}
        </div>
      </div>

      {/* 4. Prediction Residual / Model Surprise */}
      <div className={`rounded-xl p-3.5 border backdrop-blur shadow-sm ${
        residualAnomaly.isAnomaly
          ? 'border-amber-500/60 bg-amber-950/25'
          : 'border-slate-800 bg-slate-900/60'
      }`}>
        <div className={`flex items-center justify-between text-xs font-mono mb-1.5 ${
          residualAnomaly.isAnomaly ? 'text-amber-300' : 'text-slate-400'
        }`}>
          <span>MODEL SURPRISE</span>
          <Zap className={`w-3.5 h-3.5 ${residualAnomaly.isAnomaly ? 'text-amber-400 animate-pulse' : 'text-slate-500'}`} />
        </div>
        {residualAnomaly.isAnomaly ? (
          <>
            <div className="inline-flex max-w-full items-center rounded px-1.5 py-1 text-[10px] font-bold font-mono text-amber-200 bg-amber-500/15 border border-amber-400/40 animate-pulse">
              ⚡ Model Surprised — {residualLabel}
            </div>
            <div className="mt-2 text-[11px] font-mono text-amber-200/80 truncate">
              Score: {residualAnomaly.residualScore.toFixed(2)}{topResidualFeature ? ` · ${topResidualFeature.displayName}` : ''}
            </div>
          </>
        ) : (
          <>
            <div className="flex items-center gap-1.5 text-sm font-bold font-mono text-slate-300">
              <span className="h-2 w-2 rounded-full bg-slate-500" />
              Model Nominal
            </div>
            <div className="mt-2 text-[11px] font-mono text-slate-500">
              No material prediction residual
            </div>
          </>
        )}
      </div>

      {/* 5. Forecasted Next Stage */}
      <div className="rounded-xl p-3.5 border border-cyan-900/40 bg-cyan-950/20 backdrop-blur shadow-sm">
        <div className="flex items-center justify-between text-xs font-mono text-cyan-400 mb-1.5">
          <span>PREDICTED NEXT</span>
          <ArrowRight className="w-3.5 h-3.5 text-cyan-400" />
        </div>
        <div
          className="text-sm font-bold font-mono truncate"
          style={{ color: nextInfo.color }}
          title={nextInfo.label}
        >
          {predictedNextStage.replace(/_/g, ' ')}
        </div>
        <div className="text-[11px] text-cyan-300/70 mt-1 flex items-center space-x-1 font-mono">
          <span>Transition in ~10-20s</span>
        </div>
      </div>

      {/* 6. Early-Warning Lead Time */}
      <div className="rounded-xl p-3.5 border border-emerald-900/40 bg-emerald-950/20 backdrop-blur shadow-sm">
        <div className="flex items-center justify-between text-xs font-mono text-emerald-400 mb-1.5">
          <span>EARLY WARNING</span>
          <Hourglass className="w-3.5 h-3.5 text-emerald-400" />
        </div>
        <div className="flex items-baseline space-x-1">
          <span className="text-2xl font-extrabold font-mono text-emerald-300">
            {earlyWarningLeadTimeSec > 0 ? `+${earlyWarningLeadTimeSec}` : '0'}
          </span>
          <span className="text-xs font-mono text-slate-400">sec</span>
        </div>
        <div className="text-[11px] text-emerald-400/80 mt-1 truncate font-mono">
          {earlyWarningLeadTimeSec > 0
            ? `${Math.round(earlyWarningLeadTimeSec / 60)}m ${earlyWarningLeadTimeSec % 60}s lead time`
            : 'Synchronous state'}
        </div>
      </div>

      {/* 7. Active Correlated Alerts */}
      <div className="rounded-xl p-3.5 border border-slate-800 bg-slate-900/60 backdrop-blur shadow-sm">
        <div className="flex items-center justify-between text-xs font-mono text-slate-400 mb-1.5">
          <span>ACTIVE ALERTS</span>
          <AlertOctagon className={`w-3.5 h-3.5 ${activeAlertCount > 0 ? 'text-amber-400' : 'text-slate-500'}`} />
        </div>
        <div className="flex items-baseline space-x-1">
          <span className={`text-2xl font-extrabold font-mono ${activeAlertCount > 0 ? 'text-amber-400' : 'text-slate-200'}`}>
            {activeAlertCount}
          </span>
          <span className="text-xs font-mono text-slate-500">incidents</span>
        </div>
        <div className="text-[11px] text-slate-400 mt-1 font-mono">
          {activeAlertCount > 0 ? 'Deduplicated stream' : 'No active alerts'}
        </div>
      </div>
    </div>
  );
};
