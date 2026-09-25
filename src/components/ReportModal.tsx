import React from 'react';
import { X, Download, FileText, Copy, Check, Printer } from 'lucide-react';
import { Alert, NetworkStateVector, ForecastStep, AttackStage } from '../types';

interface ReportModalProps {
  isOpen: boolean;
  onClose: () => void;
  currentAlert: Alert | null;
  currentState: NetworkStateVector;
  forecasts: ForecastStep[];
  attackProbability: number;
  currentStage: AttackStage;
  predictedNextStage: AttackStage;
  earlyWarningLeadTimeSec: number;
}

export const ReportModal: React.FC<ReportModalProps> = ({
  isOpen,
  onClose,
  currentAlert,
  currentState,
  forecasts,
  attackProbability,
  currentStage,
  predictedNextStage,
  earlyWarningLeadTimeSec,
}) => {
  if (!isOpen) return null;

  const [copied, setCopied] = React.useState(false);

  const reportId = currentAlert?.id || `INC-${Date.now().toString().slice(-6)}`;
  const timestamp = new Date().toISOString();

  const reportData = {
    report_metadata: {
      report_id: reportId,
      platform: 'CyberWorld Predictive Network Defence v1.2',
      generated_at: timestamp,
      architecture: 'LSTM World Model State Transition Dynamics P(S_t+1 | S_t)',
    },
    threat_assessment: {
      current_lifecycle_stage: currentStage,
      predicted_next_stage: predictedNextStage,
      attack_probability: Number((attackProbability * 100).toFixed(1)),
      operational_severity: attackProbability > 0.85 ? 'CRITICAL' : attackProbability > 0.65 ? 'HIGH' : 'ELEVATED',
      early_warning_lead_time_sec: earlyWarningLeadTimeSec,
    },
    telemetry_signals: {
      source_host: currentAlert?.sourceIp || '192.168.1.105',
      target_host: currentAlert?.destinationIp || '10.0.0.12',
      syn_ack_ratio: currentState.synAckRatio,
      port_diversity_pct: Number((currentState.portDiversity * 100).toFixed(1)),
      burstiness_index: currentState.burstiness,
      iat_variance_ms2: currentState.iatVarianceMs,
    },
    forward_forecast_rollout: forecasts.slice(0, 5).map((f) => ({
      horizon: `T+${f.horizonSeconds}s`,
      predicted_stage: f.predictedStage,
      probability_pct: Number((f.attackProbability * 100).toFixed(1)),
      confidence: f.confidence,
    })),
    mitre_attack_candidates: currentAlert?.mitreCandidates || [
      {
        id: 'T1046',
        name: 'Network Service Scanning',
        tactic: 'Reconnaissance',
        confidence: 0.92,
        action: 'Rate-limit source IP on perimeter firewall',
      },
    ],
    recommended_containment_playbook: currentAlert?.recommendedActions || [
      'Isolate compromised workstation from internal VLAN',
      'Revoke active Kerberos ticket-granting tokens',
      'Deploy egress sinkhole for external C2 destination',
    ],
  };

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(reportData, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadJson = () => {
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `CyberWorld_Report_${reportId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadCsv = () => {
    const csvContent = [
      'Field,Value',
      `Report ID,${reportId}`,
      `Timestamp,${timestamp}`,
      `Current Stage,${currentStage}`,
      `Predicted Next Stage,${predictedNextStage}`,
      `Attack Probability,${(attackProbability * 100).toFixed(1)}%`,
      `Early Warning Lead Time,+${earlyWarningLeadTimeSec}s`,
      `Source IP,${reportData.telemetry_signals.source_host}`,
      `Target IP,${reportData.telemetry_signals.target_host}`,
    ].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `CyberWorld_Report_${reportId}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-slate-900 border border-slate-750 rounded-2xl w-full max-w-3xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden font-mono text-xs">
        {/* Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center space-x-2">
            <FileText className="w-5 h-5 text-cyan-400" />
            <div>
              <h3 className="text-sm font-bold text-slate-100">
                CYBERWORLD SOC INCIDENT REPORT &bull; {reportId}
              </h3>
              <p className="text-[11px] text-slate-400">
                Full-spectrum forensic and forward prediction dossier
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={handleCopyJson}
              className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 flex items-center space-x-1"
              title="Copy JSON"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span className="hidden sm:inline">Copy JSON</span>
            </button>
            <button
              onClick={handleDownloadJson}
              className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-slate-700 flex items-center space-x-1"
              title="Export JSON"
            >
              <Download className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">JSON</span>
            </button>
            <button
              onClick={handleDownloadCsv}
              className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-emerald-400 border border-slate-700 flex items-center space-x-1"
              title="Export CSV"
            >
              <Download className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">CSV</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Report Content */}
        <div className="p-5 overflow-y-auto space-y-4 text-slate-300">
          {/* Executive Summary */}
          <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800">
            <h4 className="text-slate-100 font-bold uppercase text-[11px] mb-2 text-cyan-400">
              1. Executive Threat Summary
            </h4>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-[11px]">
              <div>Attack Likelihood: <strong className="text-red-400">{(attackProbability * 100).toFixed(1)}%</strong></div>
              <div>Current Stage: <strong className="text-amber-400">{currentStage}</strong></div>
              <div>Predicted Next Stage: <strong className="text-cyan-400">{predictedNextStage}</strong></div>
              <div>Early Warning Lead: <strong className="text-emerald-400">+{earlyWarningLeadTimeSec}s</strong></div>
            </div>
          </div>

          {/* Forward Rollout Table */}
          <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800">
            <h4 className="text-slate-100 font-bold uppercase text-[11px] mb-2 text-cyan-400">
              2. Forward Autoregressive Rollout (K-Steps)
            </h4>
            <div className="space-y-1 text-[11px]">
              {forecasts.slice(0, 5).map((f) => (
                <div key={f.step} className="flex justify-between py-1 border-b border-slate-850">
                  <span className="text-slate-400">Horizon T+{f.horizonSeconds}s</span>
                  <span className="font-bold text-slate-200">{f.predictedStage}</span>
                  <span className="text-amber-400">{(f.attackProbability * 100).toFixed(0)}% Likelihood</span>
                </div>
              ))}
            </div>
          </div>

          {/* JSON Preview */}
          <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 text-[10px]">
            <h4 className="text-slate-400 font-bold uppercase mb-2">3. Raw Structured JSON Record</h4>
            <pre className="text-slate-400 max-h-40 overflow-y-auto">
              {JSON.stringify(reportData, null, 2)}
            </pre>
          </div>
        </div>

        {/* Footer */}
        <div className="p-3 bg-slate-950 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-bold"
          >
            Close Report
          </button>
        </div>
      </div>
    </div>
  );
};
