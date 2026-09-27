import React, { useState, useEffect } from 'react';
import {
  FileSearch,
  ShieldAlert,
  ShieldCheck,
  Clock,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  Send,
  Lock,
  Flame,
  Radio,
  ExternalLink,
  ChevronLeft,
  Zap,
  Undo2,
  Check,
  Ban,
  Activity,
  Cpu,
} from 'lucide-react';
import { Alert, NetworkFlow } from '../types';
import { ATTACK_STAGE_INFO } from '../mockData/scenarios';
import { IOCEnrichmentCard } from './IOCEnrichmentCard';
import { VulnerabilityCorrelationPanel } from './VulnerabilityCorrelationPanel';
import { correlateForecastToVulnerabilities } from '../engine/worldModelSimulator';
import {
  applyMitigation,
  rollbackMitigation,
  fetchActiveMitigations,
  fetchMitigationPolicy,
  updateMitigationPolicy,
  MitigationAction,
  MitigationPolicy,
} from '../api/cyberWorldApi';

interface InvestigationViewProps {
  selectedAlert: Alert | null;
  onBackToAlerts: () => void;
  onUpdateAnalystNotes: (alertId: string, notes: string) => void;
}

export const InvestigationView: React.FC<InvestigationViewProps> = ({
  selectedAlert,
  onBackToAlerts,
  onUpdateAnalystNotes,
}) => {
  if (!selectedAlert) {
    return (
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-12 text-center shadow-sm">
        <FileSearch className="w-10 h-10 text-slate-500 mx-auto mb-3" />
        <h3 className="text-sm font-bold font-mono text-slate-300">No Alert Selected for Investigation</h3>
        <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
          Please select an alert from the Alerts & Incidents table or click "Investigate" from any threat notification card to launch the forensic dossier.
        </p>
        <button
          onClick={onBackToAlerts}
          className="mt-4 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono"
        >
          Go to Alerts Table
        </button>
      </div>
    );
  }

  const [notes, setNotes] = useState(selectedAlert.analystNotes || '');
  const [actionsTaken, setActionsTaken] = useState<string[]>([]);
  const [isSaved, setIsSaved] = useState(false);

  // Pillar 2: Closed-Loop Active Defense State
  const [activeMitigations, setActiveMitigations] = useState<MitigationAction[]>([]);
  const [policy, setPolicy] = useState<MitigationPolicy | null>(null);
  const [mitigatingAction, setMitigatingAction] = useState<string | null>(null);
  const [mitigationMessage, setMitigationMessage] = useState<string | null>(null);
  const [mitigationError, setMitigationError] = useState<string | null>(null);

  const refreshMitigations = () => {
    fetchActiveMitigations().then(setActiveMitigations).catch(() => {});
    fetchMitigationPolicy().then(setPolicy).catch(() => {});
  };

  useEffect(() => {
    refreshMitigations();
    const interval = setInterval(refreshMitigations, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleApplyContainment = async (actionText: string, idx: number) => {
    setMitigatingAction(`act-${idx}`);
    setMitigationError(null);
    setMitigationMessage(null);
    try {
      const isEgress = actionText.toLowerCase().includes('outbound') || actionText.toLowerCase().includes('egress');
      const actionType = isEgress ? 'DROP_EGRESS' : 'DROP_INGRESS';
      const targetIp = isEgress ? selectedAlert.destinationIp : selectedAlert.sourceIp;

      const record = await applyMitigation({
        target_ip: targetIp,
        target_stage: selectedAlert.predictedNextStage,
        action_type: actionType,
        execution_mode: 'LIVE',
        expiry_minutes: 30,
        alert_id: selectedAlert.id,
        notes: actionText,
      });

      setMitigationMessage(`⚡ Neutralized! Rule ${record.action_id} active on ${targetIp}. Auto-rollback in 30 mins.`);
      setTimeout(() => setMitigationMessage(null), 7000);
      refreshMitigations();
      if (!actionsTaken.includes(`act-${idx}`)) {
        setActionsTaken([...actionsTaken, `act-${idx}`]);
      }
    } catch (err: any) {
      setMitigationError(err.message || 'Mitigation failed');
      setTimeout(() => setMitigationError(null), 5000);
    } finally {
      setMitigatingAction(null);
    }
  };

  const handleRollback = async (actionId: string) => {
    try {
      await rollbackMitigation(actionId, 'Analyst Manual Unblock');
      setMitigationMessage(`↩️ Rule ${actionId} rolled back successfully. Target unblocked.`);
      setTimeout(() => setMitigationMessage(null), 5000);
      refreshMitigations();
    } catch (err: any) {
      setMitigationError(err.message || 'Rollback failed');
      setTimeout(() => setMitigationError(null), 5000);
    }
  };

  const handleTogglePolicyMode = async () => {
    if (!policy) return;
    const newMode = policy.policy_mode === 'MANUAL_APPROVAL' ? 'AUTONOMOUS_PREDICTIVE' : 'MANUAL_APPROVAL';
    try {
      const updated = await updateMitigationPolicy(newMode, policy.auto_contain_threshold);
      setPolicy(updated);
    } catch (err: any) {
      setMitigationError(err.message || 'Policy update failed');
      setTimeout(() => setMitigationError(null), 4000);
    }
  };

  const handleSaveNotes = () => {
    onUpdateAnalystNotes(selectedAlert.id, notes);
    setIsSaved(true);
    setTimeout(() => setIsSaved(false), 2000);
  };

  const toggleAction = (act: string) => {
    if (actionsTaken.includes(act)) {
      setActionsTaken(actionsTaken.filter((a) => a !== act));
    } else {
      setActionsTaken([...actionsTaken, act]);
    }
  };

  const currentInfo = ATTACK_STAGE_INFO[selectedAlert.currentStage] || ATTACK_STAGE_INFO.BENIGN;
  const nextInfo = ATTACK_STAGE_INFO[selectedAlert.predictedNextStage] || ATTACK_STAGE_INFO.BENIGN;
  const vulnerabilityCorrelation = correlateForecastToVulnerabilities(
    selectedAlert.destinationIp,
    selectedAlert.predictedNextStage,
    selectedAlert.mitreCandidates,
  );

  return (
    <div className="space-y-5">
      {/* Top Header & Breadcrumb */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <button
            onClick={onBackToAlerts}
            className="text-xs text-slate-400 hover:text-slate-200 flex items-center space-x-1 font-mono mb-2"
          >
            <ChevronLeft className="w-3.5 h-3.5" />
            <span>Back to All Alerts</span>
          </button>
          <div className="flex items-center space-x-3">
            <span className="p-2 rounded-lg bg-red-950/60 border border-red-800/60 text-red-400">
              <ShieldAlert className="w-5 h-5" />
            </span>
            <div>
              <div className="flex items-center space-x-2">
                <h3 className="text-sm font-bold font-mono text-slate-100">
                  INCIDENT INVESTIGATION DOSSIER: {selectedAlert.id}
                </h3>
                <span className="text-[10px] px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800 font-mono font-bold">
                  {selectedAlert.severity}
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                  Status: {selectedAlert.status}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5 font-mono">
                Initiated at {selectedAlert.timestamp} &bull; Adversary Target: {selectedAlert.sourceIp} &rarr; {selectedAlert.destinationIp}
              </p>
            </div>
          </div>
        </div>

        {/* Lead time metric */}
        <div className="flex items-center space-x-3 bg-slate-950 px-3.5 py-2 rounded-lg border border-slate-800 font-mono text-xs">
          <Clock className="w-4 h-4 text-emerald-400" />
          <div>
            <div className="text-emerald-400 font-bold text-sm">+{selectedAlert.earlyWarningSeconds}s Lead Time</div>
            <div className="text-[10px] text-slate-500">Anticipation Advantage</div>
          </div>
        </div>
      </div>

      {/* Incident Summary Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3 font-mono text-xs">
        <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
          <span className="text-slate-500 text-[10px] uppercase">Attack Likelihood P(A)</span>
          <div className="text-lg font-bold text-slate-100 mt-0.5">
            {(selectedAlert.attackProbability * 100).toFixed(1)}%
          </div>
          <span className="text-[10px] text-slate-400">Confidence: {(selectedAlert.confidence * 100).toFixed(0)}%</span>
        </div>

        <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
          <span className="text-slate-500 text-[10px] uppercase">Current Lifecycle Stage</span>
          <div className="text-sm font-bold mt-0.5 truncate" style={{ color: currentInfo.color }}>
            {selectedAlert.currentStage.replace(/_/g, ' ')}
          </div>
          <span className="text-[10px] text-slate-400">{currentInfo.label}</span>
        </div>

        <div className="p-3 rounded-lg bg-slate-900/80 border border-cyan-900/40 bg-cyan-950/10">
          <span className="text-cyan-400 text-[10px] uppercase">Predicted Next Stage</span>
          <div className="text-sm font-bold mt-0.5 truncate" style={{ color: nextInfo.color }}>
            {selectedAlert.predictedNextStage.replace(/_/g, ' ')}
          </div>
          <span className="text-[10px] text-cyan-300/70">Horizon: ~{selectedAlert.forecastHorizonSteps * 10}s</span>
        </div>

        <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
          <span className="text-slate-500 text-[10px] uppercase">Involved Endpoints</span>
          <div className="text-xs font-bold text-amber-400 mt-0.5 truncate">
            {selectedAlert.sourceIp}
          </div>
          <span className="text-[10px] text-slate-400 truncate">Target: {selectedAlert.destinationIp} ({selectedAlert.dstPortSummary})</span>
        </div>
      </div>

      <section>
        <div className="mb-3 flex items-center gap-2">
          <h4 className="text-xs font-bold font-mono uppercase tracking-wider text-slate-300">IOC Enrichment</h4>
          <span className="text-[10px] font-mono text-slate-500">Cached lookup with offline demo fallback</span>
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <IOCEnrichmentCard ip={selectedAlert.sourceIp} label="Source" />
          <IOCEnrichmentCard
            ip={selectedAlert.destinationIp}
            label={selectedAlert.predictedNextStage === 'COMMAND_AND_CONTROL' ? 'C2 Server' : 'Destination'}
          />
        </div>
      </section>

      <VulnerabilityCorrelationPanel correlation={vulnerabilityCorrelation} />

      {/* MITRE ATT&CK Mapping & Evidence */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
        <h4 className="text-xs font-bold font-mono uppercase text-slate-300 tracking-wider mb-3 flex items-center space-x-2">
          <span>MITRE ATT&CK Matrix Grounding & Telemetry Evidence</span>
          <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-400">
            Non-Proof Hypothesis Layer
          </span>
        </h4>

        <div className="space-y-3">
          {selectedAlert.mitreCandidates.map((cand) => (
            <div key={cand.id} className="p-3.5 rounded-lg bg-slate-950/70 border border-slate-800 text-xs">
              <div className="flex flex-wrap items-center justify-between gap-2 mb-2 font-mono">
                <div className="flex items-center space-x-2">
                  <span className="px-2 py-0.5 rounded bg-amber-950 text-amber-400 border border-amber-800/80 font-bold">
                    {cand.id}
                  </span>
                  <span className="font-bold text-slate-200 text-sm">{cand.name}</span>
                  <span className="text-slate-500 text-[11px]">({cand.tactic})</span>
                </div>
                <span className="text-cyan-400 font-mono text-[11px]">
                  Confidence: {(cand.confidence * 100).toFixed(0)}%
                </span>
              </div>

              <div className="space-y-1 my-2">
                <span className="text-slate-400 text-[11px] font-semibold">Corroborating Evidence Signals:</span>
                <ul className="list-disc list-inside space-y-0.5 text-slate-300 text-[11px] font-mono">
                  {cand.evidence.map((ev, i) => (
                    <li key={i}>{ev}</li>
                  ))}
                </ul>
              </div>

              <div className="mt-3 pt-2.5 border-t border-slate-850 flex items-center justify-between">
                <span className="text-[11px] text-emerald-300 font-mono">
                  <strong>Playbook:</strong> {cand.recommendedAction}
                </span>
                <button
                  onClick={() => toggleAction(`mitre-${cand.id}`)}
                  className={`px-2.5 py-1 rounded text-[11px] font-mono font-semibold transition-colors ${
                    actionsTaken.includes(`mitre-${cand.id}`)
                      ? 'bg-emerald-600 text-white'
                      : 'bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700'
                  }`}
                >
                  {actionsTaken.includes(`mitre-${cand.id}`) ? 'Applied Action' : 'Execute Action'}
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Two Columns: Actionable Response Playbooks & Analyst Investigation Notes */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Playbook Containment Actions */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between mb-2">
            <h4 className="text-xs font-bold font-mono uppercase text-slate-300 tracking-wider flex items-center space-x-1.5">
              <Zap className="w-3.5 h-3.5 text-rose-400" />
              <span>Closed-Loop Containment Playbook (SOAR)</span>
            </h4>
            <span className="text-[10px] px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 font-mono">
              Auto-Rollback: 30m
            </span>
          </div>

          <p className="text-xs text-slate-400 mb-3">
            One-click automated countermeasures generated from the forward world model prediction:
          </p>

          {mitigationMessage && (
            <div className="mb-3 p-2.5 rounded-lg bg-emerald-950/60 border border-emerald-700/60 text-emerald-300 text-xs font-mono flex items-center space-x-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>{mitigationMessage}</span>
            </div>
          )}

          {mitigationError && (
            <div className="mb-3 p-2.5 rounded-lg bg-rose-950/60 border border-rose-700/60 text-rose-300 text-xs font-mono flex items-center space-x-2">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{mitigationError}</span>
            </div>
          )}

          <div className="space-y-2">
            {selectedAlert.recommendedActions.map((action, idx) => {
              const isApplied = actionsTaken.includes(`act-${idx}`);
              const isProcessing = mitigatingAction === `act-${idx}`;

              return (
                <div
                  key={idx}
                  className="p-3 rounded-lg bg-slate-950/60 border border-slate-800 flex items-center justify-between text-xs font-mono"
                >
                  <div className="pr-2">
                    <span className="text-slate-200 block">{action}</span>
                    <span className="text-[10px] text-slate-500">
                      Target: <strong className="text-cyan-400">{selectedAlert.sourceIp}</strong> &bull; Action: <strong className="text-amber-400">Host Firewall Drop</strong>
                    </span>
                  </div>
                  <div className="flex items-center space-x-2 shrink-0">
                    {isApplied ? (
                      <span className="flex items-center space-x-1 px-3 py-1.5 rounded bg-emerald-950 border border-emerald-700 text-emerald-300 text-xs font-bold">
                        <Check className="w-3.5 h-3.5" />
                        <span>Active</span>
                      </span>
                    ) : (
                      <button
                        onClick={() => handleApplyContainment(action, idx)}
                        disabled={isProcessing}
                        className="flex items-center space-x-1.5 px-3 py-1.5 rounded text-xs font-bold bg-rose-600 hover:bg-rose-500 text-white shadow-rose-950/50 transition-all border border-rose-400 disabled:opacity-50"
                      >
                        <Zap className="w-3.5 h-3.5" />
                        <span>{isProcessing ? 'Deploying...' : '1-Click Mitigate'}</span>
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Analyst Investigation Notes Editor */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm flex flex-col justify-between">
          <div>
            <h4 className="text-xs font-bold font-mono uppercase text-slate-300 tracking-wider mb-1">
              Analyst Investigation Notes
            </h4>
            <p className="text-xs text-slate-400 mb-2">
              Attach SOC observations and escalation rationale to this incident file.
            </p>

            <textarea
              rows={4}
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="e.g., Confirmed abnormal SYN flood from 192.168.1.105 targeting domain controller. Forward model predicts Initial Access within 20s. Firewall block rule 4022 queued."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs text-slate-200 font-mono focus:outline-none focus:border-emerald-500"
            />
          </div>

          <div className="mt-3 flex items-center justify-between pt-2 border-t border-slate-800 text-xs font-mono">
            <span className="text-emerald-400">
              {isSaved ? 'Notes updated in SQLite!' : 'Drafting'}
            </span>
            <button
              onClick={handleSaveNotes}
              className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs"
            >
              Save Incident Note
            </button>
          </div>
        </div>
      </div>

      {/* Active SOAR Containments & Guardrails Registry (Pillar 2) */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between pb-3 border-b border-slate-800 gap-3">
          <div>
            <div className="flex items-center space-x-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <h4 className="text-xs font-bold font-mono uppercase text-slate-200 tracking-wider">
                SOAR Active Quarantine Registry & Safety Guardrails
              </h4>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Live containment rules enforced across network endpoints with autonomous rollback safety timers.
            </p>
          </div>

          <div className="flex items-center space-x-2">
            <span className="text-xs font-mono text-slate-400">Policy:</span>
            <button
              onClick={handleTogglePolicyMode}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition-all border ${
                policy?.policy_mode === 'AUTONOMOUS_PREDICTIVE'
                  ? 'bg-rose-950 text-rose-300 border-rose-700 shadow-rose-950/30'
                  : 'bg-slate-800 text-slate-300 border-slate-700'
              }`}
            >
              <Cpu className="w-3.5 h-3.5" />
              <span>
                {policy?.policy_mode === 'AUTONOMOUS_PREDICTIVE'
                  ? '🤖 AUTONOMOUS PREDICTIVE SOAR'
                  : '👤 MANUAL ANALYST APPROVAL'}
              </span>
            </button>
          </div>
        </div>

        {/* Safety Whitelist Banner */}
        <div className="p-2.5 rounded-lg bg-slate-950/80 border border-slate-800 flex items-center justify-between text-xs font-mono">
          <span className="text-slate-400 flex items-center space-x-2">
            <Lock className="w-3.5 h-3.5 text-cyan-400" />
            <span>Infrastructure Whitelist Guardrail: Gateway (192.168.1.1), DNS (8.8.8.8, 1.1.1.1), and localhost (127.0.0.1) are protected from isolation.</span>
          </span>
          <span className="text-emerald-400 text-[11px] font-bold">100% Protected</span>
        </div>

        {/* Active Rules List */}
        {activeMitigations.length === 0 ? (
          <div className="p-4 rounded-lg bg-slate-950/40 border border-dashed border-slate-800 text-center text-xs font-mono text-slate-500">
            No active quarantine rules currently enforced. Execute a playbook action above to test 1-click proactive mitigation.
          </div>
        ) : (
          <div className="space-y-2">
            {activeMitigations.map((m) => (
              <div
                key={m.action_id}
                className="p-3 rounded-lg bg-slate-950/80 border border-slate-800/80 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs font-mono"
              >
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="font-bold text-rose-400">{m.action_id}</span>
                    <span className="text-slate-400">&bull; Target:</span>
                    <strong className="text-slate-200">{m.target_ip}</strong>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-rose-950/80 text-rose-300 border border-rose-800">
                      {m.action_type}
                    </span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                      {m.execution_mode}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-500 mt-1 truncate max-w-xl">
                    Command: <code className="text-cyan-300">{m.command_executed}</code>
                  </div>
                  <div className="text-[10px] text-slate-500 mt-0.5">
                    Applied: {m.applied_at} &bull; Expires: {m.expires_at || 'Manual'} &bull; By: {m.analyst}
                  </div>
                </div>

                <div className="flex items-center space-x-2 shrink-0">
                  <button
                    onClick={() => handleRollback(m.action_id)}
                    className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-amber-300 border border-amber-700/60 text-xs font-mono font-bold transition-all"
                  >
                    <Undo2 className="w-3.5 h-3.5" />
                    <span>Rollback / Unblock</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
