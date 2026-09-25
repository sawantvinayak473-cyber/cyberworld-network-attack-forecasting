import React, { useMemo } from 'react';
import { AttackStage, ForecastStep } from '../types';
import { ATTACK_STAGE_INFO } from '../mockData/scenarios';

interface AttackDigitalTwinProps {
  predictedCurrentStage: AttackStage;
  predictedNextStage: AttackStage;
  attackProbability: number;
  forecasts: ForecastStep[];
  earlyWarningLeadTimeSec: number;
}

const STAGES: AttackStage[] = [
  'BENIGN',
  'RECONNAISSANCE',
  'INITIAL_ACCESS',
  'LATERAL_MOVEMENT',
  'COMMAND_AND_CONTROL',
  'EXFILTRATION',
];

const NODE_POSITIONS = [
  { x: 105, y: 260 },
  { x: 290, y: 165 },
  { x: 485, y: 105 },
  { x: 690, y: 125 },
  { x: 895, y: 185 },
  { x: 1090, y: 270 },
];

function transitionColor(probability: number) {
  if (probability >= 0.85) return '#ef4444';
  if (probability >= 0.35) return '#f59e0b';
  return '#10b981';
}

function transitionMarker(probability: number) {
  if (probability >= 0.85) return 'url(#cyberworld-twin-arrow-critical)';
  if (probability >= 0.35) return 'url(#cyberworld-twin-arrow-elevated)';
  return 'url(#cyberworld-twin-arrow-safe)';
}

function curvedPath(from: { x: number; y: number }, to: { x: number; y: number }) {
  const midpointX = (from.x + to.x) / 2;
  const midpointY = Math.min(from.y, to.y) - 54;
  return `M ${from.x} ${from.y} Q ${midpointX} ${midpointY} ${to.x} ${to.y}`;
}

function curveMidpoint(from: { x: number; y: number }, to: { x: number; y: number }) {
  const control = { x: (from.x + to.x) / 2, y: Math.min(from.y, to.y) - 54 };
  return {
    x: (from.x + 2 * control.x + to.x) / 4,
    y: (from.y + 2 * control.y + to.y) / 4,
  };
}

export const AttackDigitalTwin: React.FC<AttackDigitalTwinProps> = ({
  predictedCurrentStage,
  predictedNextStage,
  attackProbability,
  forecasts,
  earlyWarningLeadTimeSec,
}) => {
  const currentStageIndex = Math.max(0, STAGES.indexOf(predictedCurrentStage));
  const currentPosition = NODE_POSITIONS[currentStageIndex];
  const nextStageIndex = Math.max(0, STAGES.indexOf(predictedNextStage));
  const nextPosition = NODE_POSITIONS[nextStageIndex];
  const primaryPath = curvedPath(currentPosition, nextPosition);
  const particleMidpoint = curveMidpoint(currentPosition, nextPosition);
  const primaryProbability = forecasts[0]?.attackProbability ?? attackProbability;

  const stageProbabilities = useMemo(() => (
    STAGES.reduce<Record<AttackStage, number>>((probabilities, stage) => {
      const forecastProbability = forecasts
        .filter((forecast) => forecast.predictedStage === stage)
        .reduce((maximum, forecast) => Math.max(maximum, forecast.attackProbability), 0);
      const baseProbability = stage === 'BENIGN'
        ? Math.max(0.04, 1 - attackProbability)
        : 0.04;

      probabilities[stage] = Math.max(
        baseProbability,
        forecastProbability,
        stage === predictedCurrentStage ? attackProbability : 0,
      );
      return probabilities;
    }, {} as Record<AttackStage, number>)
  ), [attackProbability, forecasts, predictedCurrentStage]);

  return (
    <section className="rounded-xl border border-slate-800 bg-slate-900/55 p-4 sm:p-5 shadow-sm overflow-hidden">
      <style>{`
        @keyframes cyberworld-twin-glow {
          0%, 100% { filter: drop-shadow(0 0 3px rgba(16, 185, 129, .45)); }
          50% { filter: drop-shadow(0 0 13px rgba(16, 185, 129, .95)); }
        }
        @keyframes cyberworld-twin-dash { to { stroke-dashoffset: -22; } }
        @keyframes cyberworld-twin-particle {
          0% { cx: ${currentPosition.x}px; cy: ${currentPosition.y}px; opacity: .3; }
          50% { cx: ${particleMidpoint.x}px; cy: ${particleMidpoint.y}px; opacity: 1; }
          100% { cx: ${nextPosition.x}px; cy: ${nextPosition.y}px; opacity: .3; }
        }
        .cyberworld-twin-active { animation: cyberworld-twin-glow 1.6s ease-in-out infinite; }
        .cyberworld-twin-path { animation: cyberworld-twin-dash 1s linear infinite; }
        .cyberworld-twin-particle { animation: cyberworld-twin-particle 2s ease-in-out infinite; }
        .cyberworld-twin-tooltip { opacity: 0; pointer-events: none; transition: opacity 150ms ease; }
        .cyberworld-twin-node:hover .cyberworld-twin-tooltip,
        .cyberworld-twin-node:focus .cyberworld-twin-tooltip { opacity: 1; }
        @media (prefers-reduced-motion: reduce) {
          .cyberworld-twin-active, .cyberworld-twin-path, .cyberworld-twin-particle { animation: none; }
        }
      `}</style>

      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-xs font-mono tracking-[0.2em] text-emerald-400">ATTACK DIGITAL TWIN</p>
          <h2 className="mt-1 text-lg font-bold text-slate-100">Projected intrusion state trajectory</h2>
        </div>
        <div className="rounded-md border border-emerald-900/60 bg-emerald-950/30 px-3 py-2 text-right font-mono text-xs">
          <div className="text-slate-400">Primary transition</div>
          <div className="mt-0.5 text-emerald-300">
            {predictedCurrentStage.replace(/_/g, ' ')} <span className="text-slate-500">→</span> {predictedNextStage.replace(/_/g, ' ')}
          </div>
        </div>
      </div>

      <div className="w-full overflow-x-auto">
        <svg
          className="min-w-[680px] w-full h-auto"
          viewBox="0 0 1200 390"
          role="img"
          aria-label={`Attack Digital Twin transition from ${predictedCurrentStage} to ${predictedNextStage}`}
        >
          <title>Attack Digital Twin projected intrusion trajectory</title>
          <desc>Six attack stages connected by weighted transition paths. The highlighted path is the current model prediction.</desc>
          <defs>
            <marker id="cyberworld-twin-arrow-safe" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto">
              <path d="M 0 0 L 8 4 L 0 8 z" fill="#10b981" />
            </marker>
            <marker id="cyberworld-twin-arrow-elevated" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto">
              <path d="M 0 0 L 8 4 L 0 8 z" fill="#f59e0b" />
            </marker>
            <marker id="cyberworld-twin-arrow-critical" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="6" markerHeight="6" orient="auto">
              <path d="M 0 0 L 8 4 L 0 8 z" fill="#ef4444" />
            </marker>
            <filter id="cyberworld-twin-particle-glow" x="-100%" y="-100%" width="300%" height="300%">
              <feGaussianBlur stdDeviation="5" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          {STAGES.slice(0, -1).map((stage, index) => {
            const from = NODE_POSITIONS[index];
            const to = NODE_POSITIONS[index + 1];
            const probability = forecasts[index]?.attackProbability ?? 0.12;
            const isPrimary = stage === predictedCurrentStage && STAGES[index + 1] === predictedNextStage;

            return (
              <path
                key={`${stage}-${STAGES[index + 1]}`}
                d={curvedPath(from, to)}
                fill="none"
                stroke={transitionColor(probability)}
                strokeOpacity={isPrimary ? 0.82 : 0.34}
                strokeWidth={2 + probability * 5}
                strokeLinecap="round"
                markerEnd={transitionMarker(probability)}
              />
            );
          })}

          <path
            d={primaryPath}
            className="cyberworld-twin-path"
            fill="none"
            stroke={transitionColor(primaryProbability)}
            strokeWidth={3 + primaryProbability * 4}
            strokeDasharray="8 7"
            strokeLinecap="round"
            markerEnd={transitionMarker(primaryProbability)}
          />
          <circle
            className="cyberworld-twin-particle"
            cx={currentPosition.x}
            cy={currentPosition.y}
            r="7"
            fill="#d1fae5"
            filter="url(#cyberworld-twin-particle-glow)"
          />

          {STAGES.map((stage, index) => {
            const position = NODE_POSITIONS[index];
            const stageInfo = ATTACK_STAGE_INFO[stage];
            const probability = Math.min(1, stageProbabilities[stage]);
            const radius = 33 + probability * 22;
            const nodeOpacity = index > currentStageIndex ? 0.4 : index === currentStageIndex ? 1 : 0.7;
            const isCurrent = stage === predictedCurrentStage;
            const remainingLeadTime = Math.max(0, earlyWarningLeadTimeSec - Math.max(0, index - currentStageIndex) * 10);
            const tooltipY = Math.max(12, position.y - radius - 70);

            return (
              <g
                key={stage}
                className={`cyberworld-twin-node ${isCurrent ? 'cyberworld-twin-active' : ''}`}
                opacity={nodeOpacity}
              >
                <title>{`${stageInfo.label}: ${(probability * 100).toFixed(0)}%, ${remainingLeadTime}s early warning remaining`}</title>
                <circle
                  cx={position.x}
                  cy={position.y}
                  r={radius}
                  fill={stageInfo.color}
                  fillOpacity="0.2"
                  stroke={stageInfo.color}
                  strokeWidth={isCurrent ? 3 : 1.5}
                />
                <circle
                  cx={position.x}
                  cy={position.y}
                  r={Math.max(18, radius - 13)}
                  fill="#090d16"
                  fillOpacity="0.92"
                />
                <text
                  x={position.x}
                  y={position.y - 4}
                  textAnchor="middle"
                  fill={stageInfo.color}
                  fontSize="11"
                  fontWeight="700"
                  fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
                >
                  {stage.replace(/_/g, ' ')}
                </text>
                <text
                  x={position.x}
                  y={position.y + 15}
                  textAnchor="middle"
                  fill="#cbd5e1"
                  fontSize="13"
                  fontWeight="700"
                  fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
                >
                  {(probability * 100).toFixed(0)}%
                </text>
                <g className="cyberworld-twin-tooltip">
                  <rect
                    x={position.x - 80}
                    y={tooltipY}
                    width="160"
                    height="48"
                    rx="6"
                    fill="#0f172a"
                    stroke={stageInfo.color}
                    strokeOpacity="0.8"
                  />
                  <text x={position.x} y={tooltipY + 18} textAnchor="middle" fill="#e2e8f0" fontSize="11" fontFamily="ui-monospace, monospace">
                    {stage.replace(/_/g, ' ')} · {(probability * 100).toFixed(1)}%
                  </text>
                  <text x={position.x} y={tooltipY + 35} textAnchor="middle" fill="#94a3b8" fontSize="10" fontFamily="ui-monospace, monospace">
                    +{remainingLeadTime}s warning remaining
                  </text>
                </g>
              </g>
            );
          })}
        </svg>
      </div>

      <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-[11px] font-mono text-slate-400">
        <span><span className="text-emerald-400">●</span> Safe transition</span>
        <span><span className="text-amber-400">●</span> Elevated transition</span>
        <span><span className="text-red-400">●</span> Critical transition</span>
        <span className="text-slate-500">Hover a stage for probability and remaining lead time</span>
      </div>
    </section>
  );
};
