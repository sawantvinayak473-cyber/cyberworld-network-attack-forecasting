import React, { useState } from 'react';
import {
  Play,
  Pause,
  RotateCcw,
  StepForward,
  Radio,
  Sliders,
  CheckCircle,
  AlertCircle,
  Clock,
  Layers,
  Activity,
  ArrowRight,
} from 'lucide-react';
import {
  NetworkFlow,
  NetworkStateVector,
  SimulationScenario,
  AttackStage,
} from '../types';
import { ATTACK_STAGE_INFO, SIMULATION_SCENARIOS } from '../mockData/scenarios';

interface LiveMonitorViewProps {
  allStates: NetworkStateVector[];
  allFlows: NetworkFlow[];
  currentWindow: number;
  isSimulating: boolean;
  onToggleSimulate: () => void;
  onStepForward: () => void;
  onResetSimulation: () => void;
  simSpeed: number;
  setSimSpeed: (speed: number) => void;
  activeScenarioId: string;
  onSelectScenario: (id: string) => void;
  attackProbability: number;
  currentStage: AttackStage;
}

export const LiveMonitorView: React.FC<LiveMonitorViewProps> = ({
  allStates,
  allFlows,
  currentWindow,
  isSimulating,
  onToggleSimulate,
  onStepForward,
  onResetSimulation,
  simSpeed,
  setSimSpeed,
  activeScenarioId,
  onSelectScenario,
  attackProbability,
  currentStage,
}) => {
  const currentState = allStates[currentWindow] || allStates[0];
  const [filterOnlySuspicious, setFilterOnlySuspicious] = useState(false);

  // Flows corresponding to current and recent windows
  const currentWindowFlows = allFlows.filter((f) => {
    const minSec = Math.max(0, (currentWindow - 1) * 10);
    const maxSec = (currentWindow + 1) * 10;
    const inRange = f.timeOffsetSeconds >= minSec && f.timeOffsetSeconds <= maxSec;
    return filterOnlySuspicious ? inRange && f.isAttack : inRange;
  });

  const scenario = activeScenarioId === 'uploaded'
    ? {
      name: 'Uploaded Telemetry Replay',
      description: 'Chronological state vectors produced by the live backend ingestion pathway.',
    }
    : SIMULATION_SCENARIOS.find((s) => s.id === activeScenarioId) || SIMULATION_SCENARIOS[0];

  return (
    <div className="space-y-5">
      {/* Control Station & Live Telemetry Stream Bar */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2">
              <span className="relative flex h-3 w-3">
                <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${isSimulating ? 'bg-emerald-400' : 'bg-slate-400'} opacity-75`} />
                <span className={`relative inline-flex rounded-full h-3 w-3 ${isSimulating ? 'bg-emerald-500' : 'bg-slate-500'}`} />
              </span>
              <h3 className="text-sm font-bold text-slate-100 font-mono flex items-center space-x-2">
                <span>LIVE TELEMETRY INGESTION ENGINE</span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-normal">
                  Mode B: Chronological Stream Simulator
                </span>
              </h3>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Active Scenario: <span className="text-cyan-400 font-semibold">{scenario.name}</span> &bull; {scenario.description}
            </p>
          </div>

          {/* Interactive Controls */}
          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={onToggleSimulate}
              className={`flex items-center space-x-1.5 px-4 py-2 rounded-lg text-xs font-bold font-mono shadow transition-all ${
                isSimulating
                  ? 'bg-amber-600 hover:bg-amber-500 text-white shadow-amber-950/40'
                  : 'bg-emerald-600 hover:bg-emerald-500 text-white shadow-emerald-950/40'
              }`}
            >
              {isSimulating ? (
                <>
                  <Pause className="w-4 h-4" />
                  <span>PAUSE STREAM</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  <span>START STREAM REPLAY</span>
                </>
              )}
            </button>

            <button
              onClick={onStepForward}
              className="flex items-center space-x-1 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-mono"
              title="Advance 10 seconds"
            >
              <StepForward className="w-4 h-4" />
              <span>Step (10s)</span>
            </button>

            <button
              onClick={onResetSimulation}
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700"
              title="Reset Timeline to T=0"
            >
              <RotateCcw className="w-4 h-4" />
            </button>

            <div className="flex items-center bg-slate-950 rounded-lg border border-slate-800 p-1">
              {[0.5, 1, 2, 5].map((s) => (
                <button
                  key={s}
                  onClick={() => setSimSpeed(s)}
                  className={`px-2 py-1 text-xs font-mono rounded ${
                    simSpeed === s ? 'bg-emerald-600 text-white font-bold' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {s}x
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Timeline Scrubber */}
        <div className="mt-4 pt-3 border-t border-slate-800 flex items-center space-x-4">
          <span className="text-xs text-slate-400 font-mono whitespace-nowrap">
            Elapsed: <strong className="text-slate-200">{currentWindow * 10}s</strong> / {(allStates.length - 1) * 10}s
          </span>
          <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800 flex">
            {allStates.map((s, idx) => {
              const isPast = idx <= currentWindow;
              const isAttack = s.isGroundTruthAttack;
              return (
                <div
                  key={idx}
                  className={`h-full flex-1 transition-colors ${
                    isPast
                      ? isAttack
                        ? 'bg-red-500'
                        : 'bg-emerald-500'
                      : 'bg-slate-800'
                  } ${idx === currentWindow ? 'ring-2 ring-white z-10' : ''}`}
                  title={`Window ${idx + 1} (${s.timestamp}): ${s.groundTruthStage}`}
                />
              );
            })}
          </div>
          <span className="text-xs text-slate-400 font-mono whitespace-nowrap">
            Stage: <strong className="text-amber-400">{currentStage}</strong>
          </span>
        </div>
      </div>

      {/* Two Columns: 10-Second Network State Vector (Left) & Raw Live Flows Inspector (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left Column: 10-Second Network State Vector S(t) */}
        <div className="lg:col-span-5 bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between mb-3 border-b border-slate-800 pb-2">
            <div>
              <h4 className="text-xs font-bold font-mono uppercase text-slate-300 tracking-wider flex items-center space-x-2">
                <span>Aggregated Network State S(t)</span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                  Window #{currentWindow + 1}
                </span>
              </h4>
              <p className="text-[11px] text-slate-400">
                10-second non-overlapping feature matrix fed into World Model sequence buffer $S(t-9)\dots S(t)$.
              </p>
            </div>
            <div className="text-right text-xs font-mono text-slate-400">
              {currentState.timestamp}
            </div>
          </div>

          <div className="space-y-3 text-xs font-mono">
            {/* 1. Traffic Volume */}
            <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
              <div className="text-[11px] text-slate-400 font-semibold mb-1.5 uppercase flex items-center justify-between">
                <span>1. Traffic Volume Metrics</span>
                <span className="text-cyan-400">{currentState.flowCount} flows</span>
              </div>
              <div className="grid grid-cols-2 gap-2 text-slate-300">
                <div>Total Packets: <strong className="text-slate-100">{currentState.totalPackets}</strong></div>
                <div>Packets / Sec: <strong className="text-slate-100">{currentState.packetsPerSec}</strong></div>
                <div>Total Bytes: <strong className="text-slate-100">{(currentState.totalBytes / 1024).toFixed(1)} KB</strong></div>
                <div>Bytes / Sec: <strong className="text-slate-100">{(currentState.bytesPerSec / 1024).toFixed(1)} KB/s</strong></div>
                <div className="col-span-2">Bytes / Packet: <strong className="text-slate-100">{currentState.bytesPerPacket} bytes</strong></div>
              </div>
            </div>

            {/* 2. TCP Flags & Behaviour */}
            <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
              <div className="text-[11px] text-slate-400 font-semibold mb-1.5 uppercase flex items-center justify-between">
                <span>2. TCP Behaviour & Flag Distribution</span>
                <span className={`font-bold ${currentState.synAckRatio > 1.2 ? 'text-red-400' : 'text-emerald-400'}`}>
                  SYN/ACK: {currentState.synAckRatio}x
                </span>
              </div>
              <div className="grid grid-cols-3 gap-1.5 text-[11px]">
                <div className="bg-slate-900 p-1 rounded border border-slate-800">
                  SYN: <span className="text-slate-200 font-bold">{currentState.synCount}</span>
                </div>
                <div className="bg-slate-900 p-1 rounded border border-slate-800">
                  ACK: <span className="text-slate-200 font-bold">{currentState.ackCount}</span>
                </div>
                <div className="bg-slate-900 p-1 rounded border border-slate-800">
                  RST: <span className="text-slate-200 font-bold">{currentState.rstCount}</span>
                </div>
                <div className="bg-slate-900 p-1 rounded border border-slate-800">
                  FIN: <span className="text-slate-200 font-bold">{currentState.finCount}</span>
                </div>
                <div className="bg-slate-900 p-1 rounded border border-slate-800">
                  PSH: <span className="text-slate-200 font-bold">{currentState.pshCount}</span>
                </div>
                <div className="bg-slate-900 p-1 rounded border border-slate-800">
                  RST/Flow: <span className="text-slate-200 font-bold">{(currentState.rstFlowRatio * 100).toFixed(0)}%</span>
                </div>
              </div>
            </div>

            {/* 3. Topology Diversity & Timing */}
            <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
              <div className="text-[11px] text-slate-400 font-semibold mb-1.5 uppercase flex items-center justify-between">
                <span>3. Topology Diversity & Inter-Arrival Timing</span>
                <span className="text-amber-400">Entropy: {currentState.packetSizeEntropy}</span>
              </div>
              <div className="grid grid-cols-2 gap-2 text-slate-300">
                <div>Port Diversity: <strong className="text-slate-100">{(currentState.portDiversity * 100).toFixed(0)}%</strong></div>
                <div>Unique Dst Ports: <strong className="text-slate-100">{currentState.uniqueDstPorts}</strong></div>
                <div>Mean IAT: <strong className="text-slate-100">{currentState.meanIatMs} ms</strong></div>
                <div>IAT Variance: <strong className="text-slate-100">{currentState.iatVarianceMs} ms²</strong></div>
                <div>Burstiness Index: <strong className="text-slate-100">{currentState.burstiness}</strong></div>
                <div>Mean Flow Dur: <strong className="text-slate-100">{currentState.meanDurationMs} ms</strong></div>
              </div>
            </div>

            {/* 4. Packet-Level Telemetry */}
            <div className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
              <div className="text-[11px] text-slate-400 font-semibold mb-1.5 uppercase flex items-center justify-between">
                <span>4. Packet-Level PCAP Characteristics</span>
                <span className="text-slate-400">TTL: {currentState.meanTtl}</span>
              </div>
              <div className="grid grid-cols-2 gap-2 text-slate-300">
                <div>Payload Entropy: <strong className="text-slate-100">{currentState.packetSizeEntropy} bits</strong></div>
                <div>TTL Variance: <strong className="text-slate-100">{currentState.ttlVariance}</strong></div>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Live NetFlow / PCAP Flow Inspector Table */}
        <div className="lg:col-span-7 bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex flex-wrap items-center justify-between gap-2 mb-3 border-b border-slate-800 pb-2">
              <div>
                <h4 className="text-xs font-bold font-mono uppercase text-slate-300 tracking-wider">
                  Raw Flow Telemetry Stream
                </h4>
                <p className="text-[11px] text-slate-400">
                  Chronological network records arriving during window #{currentWindow + 1}
                </p>
              </div>

              <div className="flex items-center space-x-2 text-xs font-mono">
                <label className="flex items-center space-x-1 text-slate-400 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={filterOnlySuspicious}
                    onChange={(e) => setFilterOnlySuspicious(e.target.checked)}
                    className="rounded bg-slate-800 border-slate-700 text-emerald-500"
                  />
                  <span>Suspicious Only</span>
                </label>
                <span className="text-slate-600">|</span>
                <span className="text-cyan-400 font-bold">{currentWindowFlows.length} flows visible</span>
              </div>
            </div>

            {/* Flow Records Table */}
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 bg-slate-950/40">
                    <th className="py-2 px-2">Timestamp</th>
                    <th className="py-2 px-2">Source IP:Port</th>
                    <th className="py-2 px-2">Destination IP:Port</th>
                    <th className="py-2 px-2">Proto</th>
                    <th className="py-2 px-2">Flags</th>
                    <th className="py-2 px-2">Bytes</th>
                    <th className="py-2 px-2">IAT</th>
                    <th className="py-2 px-2">Label</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {currentWindowFlows.map((flow) => {
                    const stageInfo = ATTACK_STAGE_INFO[flow.label] || ATTACK_STAGE_INFO.BENIGN;
                    const flagsStr = [
                      flow.flags.syn && 'SYN',
                      flow.flags.ack && 'ACK',
                      flow.flags.rst && 'RST',
                      flow.flags.fin && 'FIN',
                      flow.flags.psh && 'PSH',
                    ]
                      .filter(Boolean)
                      .join(',');

                    return (
                      <tr
                        key={flow.id}
                        className={`hover:bg-slate-800/40 transition-colors ${
                          flow.isAttack ? 'bg-red-950/20' : ''
                        }`}
                      >
                        <td className="py-2 px-2 text-slate-400 whitespace-nowrap">
                          {flow.timestamp}
                        </td>
                        <td className="py-2 px-2 text-slate-200 whitespace-nowrap">
                          {flow.srcIp}:{flow.srcPort}
                        </td>
                        <td className="py-2 px-2 text-slate-200 whitespace-nowrap">
                          <span className={flow.isAttack ? 'text-amber-400 font-bold' : ''}>
                            {flow.dstIp}:{flow.dstPort}
                          </span>
                        </td>
                        <td className="py-2 px-2 text-slate-400">{flow.protocol}</td>
                        <td className="py-2 px-2 text-[10px]">
                          <span
                            className={`px-1.5 py-0.5 rounded font-mono ${
                              flow.flags.syn && !flow.flags.ack
                                ? 'bg-amber-950 text-amber-400 border border-amber-800'
                                : flow.flags.rst
                                ? 'bg-red-950 text-red-400'
                                : 'bg-slate-800 text-slate-300'
                            }`}
                          >
                            {flagsStr || 'NONE'}
                          </span>
                        </td>
                        <td className="py-2 px-2 text-slate-300">
                          {flow.bytes > 1024 ? `${(flow.bytes / 1024).toFixed(1)}K` : flow.bytes}
                        </td>
                        <td className="py-2 px-2 text-slate-400">{flow.iatMeanMs}ms</td>
                        <td className="py-2 px-2">
                          <span
                            className="px-1.5 py-0.5 rounded text-[9px] font-bold"
                            style={{
                              backgroundColor: stageInfo.bg,
                              color: stageInfo.color,
                              borderColor: stageInfo.border,
                              borderWidth: 1,
                            }}
                          >
                            {flow.label}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>
              Ingestion rate: <strong className="text-slate-200">~60 flows/10s window</strong>
            </span>
            <span className="text-emerald-400">
              Zero packet-drop in buffer &bull; Chronological order preserved
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
