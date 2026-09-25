import React, { useState } from 'react';
import {
  ShieldAlert,
  Search,
  Filter,
  Bot,
  LoaderCircle,
  FileSearch,
} from 'lucide-react';
import { Alert, AlertStatus, AlertSeverity } from '../types';
import { ATTACK_STAGE_INFO } from '../mockData/scenarios';
import { AlertFilter, translateNLQueryToFilter } from '../api/copilotApi';

interface AlertsViewProps {
  alerts: Alert[];
  onUpdateAlertStatus: (alertId: string, status: AlertStatus) => void;
  onSelectAlertForInvestigation: (alert: Alert) => void;
}

type FilterMode = 'MANUAL' | 'NL_QUERY';

function matchesNLFilter(alert: Alert, filter: AlertFilter): boolean {
  return (
    (!filter.severity || filter.severity.includes(alert.severity)) &&
    (!filter.status || filter.status.includes(alert.status)) &&
    (!filter.stage || filter.stage.includes(alert.currentStage)) &&
    (!filter.sourceIp || filter.sourceIp === alert.sourceIp) &&
    (filter.minProbability === undefined || alert.attackProbability >= filter.minProbability)
  );
}

export const AlertsView: React.FC<AlertsViewProps> = ({
  alerts,
  onUpdateAlertStatus,
  onSelectAlertForInvestigation,
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [stageFilter, setStageFilter] = useState<string>('ALL');
  const [filterMode, setFilterMode] = useState<FilterMode>('MANUAL');
  const [nlQuery, setNlQuery] = useState('');
  const [nlFilter, setNlFilter] = useState<AlertFilter | null>(null);
  const [isTranslating, setIsTranslating] = useState(false);
  const [translationError, setTranslationError] = useState('');

  const filteredAlerts = alerts.filter((alert) => {
    if (filterMode === 'NL_QUERY') {
      // The LLM result is only evaluated against this in-memory array.
      return !nlFilter || matchesNLFilter(alert, nlFilter);
    }

    const matchesSearch =
      alert.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.sourceIp.includes(searchTerm) ||
      alert.destinationIp.includes(searchTerm) ||
      alert.currentStage.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesSeverity = severityFilter === 'ALL' || alert.severity === severityFilter;
    const matchesStatus = statusFilter === 'ALL' || alert.status === statusFilter;
    const matchesStage = stageFilter === 'ALL' || alert.currentStage === stageFilter;

    return matchesSearch && matchesSeverity && matchesStatus && matchesStage;
  });

  const handleNLQuery = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const query = nlQuery.trim();
    if (!query || isTranslating) return;

    setIsTranslating(true);
    setTranslationError('');
    try {
      setNlFilter(await translateNLQueryToFilter(query));
    } catch {
      setTranslationError('Could not translate this question. Check the Copilot API configuration and try again.');
    } finally {
      setIsTranslating(false);
    }
  };

  const useSuggestion = (suggestion: string) => {
    setNlQuery(suggestion);
  };

  const getSeverityBadge = (sev: AlertSeverity) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-950 text-red-400 border-red-800';
      case 'HIGH':
        return 'bg-orange-950 text-orange-400 border-orange-800';
      case 'MEDIUM':
        return 'bg-amber-950 text-amber-400 border-amber-800';
      case 'LOW':
      default:
        return 'bg-blue-950 text-blue-400 border-blue-800';
    }
  };

  const getStatusBadge = (status: AlertStatus) => {
    switch (status) {
      case 'NEW':
        return 'bg-cyan-950 text-cyan-400 border-cyan-800 animate-pulse';
      case 'ACKNOWLEDGED':
        return 'bg-purple-950 text-purple-400 border-purple-800';
      case 'INVESTIGATING':
        return 'bg-amber-950 text-amber-400 border-amber-800';
      case 'RESOLVED':
        return 'bg-emerald-950 text-emerald-400 border-emerald-800';
      case 'FALSE_POSITIVE':
        return 'bg-slate-800 text-slate-400 border-slate-700';
    }
  };

  return (
    <div className="space-y-5">
      {/* Top Controls & Correlation Summary Banner */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h3 className="text-sm font-bold font-mono text-slate-100 flex items-center space-x-2">
              <ShieldAlert className="w-5 h-5 text-amber-400" />
              <span>CORRELATED ALERT & INCIDENT ENGINE</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Deduplicated telemetry alerts correlated into longitudinal attack campaigns with forward kill-chain stage projections.
            </p>
          </div>

          <div className="flex items-center space-x-2 text-xs font-mono">
            <span className="text-slate-400">Total Incidents:</span>
            <span className="px-2 py-0.5 rounded bg-slate-800 text-emerald-400 font-bold border border-slate-700">
              {alerts.length} Records
            </span>
          </div>
        </div>

        {/* Alert query bar */}
        <div className="mt-4 pt-3 border-t border-slate-800">
          <div className="mb-3 flex items-center gap-2 text-xs font-mono">
            <button
              type="button"
              onClick={() => setFilterMode('MANUAL')}
              className={`flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 font-semibold transition-colors ${
                filterMode === 'MANUAL'
                  ? 'border-cyan-700 bg-cyan-950/50 text-cyan-300'
                  : 'border-slate-800 bg-slate-950 text-slate-400 hover:text-slate-200'
              }`}
            >
              <Filter className="h-3.5 w-3.5" /> Manual Filter
            </button>
            <button
              type="button"
              onClick={() => setFilterMode('NL_QUERY')}
              className={`flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 font-semibold transition-colors ${
                filterMode === 'NL_QUERY'
                  ? 'border-emerald-700 bg-emerald-950/50 text-emerald-300'
                  : 'border-slate-800 bg-slate-950 text-slate-400 hover:text-slate-200'
              }`}
            >
              <Bot className="h-3.5 w-3.5" /> NL Query
            </button>
          </div>

          {filterMode === 'MANUAL' ? (
            <div className="grid grid-cols-1 gap-2.5 text-xs font-mono sm:grid-cols-2 md:grid-cols-4">
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
                <input
                  type="text"
                  placeholder="Search IP, Stage, Alert ID..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-emerald-500"
                />
              </div>

              <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-emerald-500">
                <option value="ALL">Severity: All</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>

              <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-emerald-500">
                <option value="ALL">Status: All</option>
                <option value="NEW">New</option>
                <option value="ACKNOWLEDGED">Acknowledged</option>
                <option value="INVESTIGATING">Investigating</option>
                <option value="RESOLVED">Resolved</option>
                <option value="FALSE_POSITIVE">False Positive</option>
              </select>

              <select value={stageFilter} onChange={(e) => setStageFilter(e.target.value)} className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-emerald-500">
                <option value="ALL">Stage: All</option>
                <option value="RECONNAISSANCE">Reconnaissance</option>
                <option value="INITIAL_ACCESS">Initial Access</option>
                <option value="LATERAL_MOVEMENT">Lateral Movement</option>
                <option value="COMMAND_AND_CONTROL">Command & Control</option>
                <option value="EXFILTRATION">Exfiltration</option>
              </select>
            </div>
          ) : (
            <form onSubmit={handleNLQuery} className="space-y-2">
              <div className="flex gap-2">
                <div className="relative min-w-0 flex-1">
                  <Bot className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-emerald-400" />
                  <input
                    type="text"
                    value={nlQuery}
                    onChange={(event) => setNlQuery(event.target.value)}
                    placeholder={'Ask a question about alerts... e.g. "Show CRITICAL C2 alerts"'}
                    disabled={isTranslating}
                    className="w-full rounded-lg border border-slate-800 bg-slate-950 py-1.5 pl-8 pr-3 text-xs text-slate-200 placeholder:text-slate-600 focus:border-emerald-500 focus:outline-none disabled:opacity-60"
                  />
                </div>
                <button
                  type="submit"
                  disabled={!nlQuery.trim() || isTranslating}
                  className="flex items-center gap-1.5 rounded-lg border border-emerald-700 bg-emerald-950/50 px-3 py-1.5 text-xs font-bold text-emerald-300 hover:bg-emerald-900/50 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {isTranslating ? <LoaderCircle className="h-3.5 w-3.5 animate-spin" /> : <Search className="h-3.5 w-3.5" />}
                  {isTranslating ? 'Translating' : 'Apply'}
                </button>
              </div>
              <div className="flex flex-wrap items-center gap-1.5 text-[10px] font-mono">
                <span className="text-slate-500">Try:</span>
                {['Show CRITICAL C2 alerts', 'Alerts from 192.168.1.105', 'Unresolved lateral movement'].map((suggestion) => (
                  <button
                    type="button"
                    key={suggestion}
                    onClick={() => useSuggestion(suggestion)}
                    className="rounded border border-slate-700 bg-slate-950 px-1.5 py-0.5 text-slate-400 hover:border-emerald-800 hover:text-emerald-300"
                  >
                    {suggestion}
                  </button>
                ))}
              </div>
              {nlFilter && !translationError && (
                <p className="text-[10px] font-mono text-emerald-400">Natural-language filter applied to local alert results.</p>
              )}
              {translationError && <p className="text-[10px] font-mono text-amber-400">{translationError}</p>}
            </form>
          )}
        </div>
      </div>

      {/* Alerts Table */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 bg-slate-950/50">
                <th className="py-2.5 px-3">Alert ID</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Time</th>
                <th className="py-2.5 px-3">Source &rarr; Target</th>
                <th className="py-2.5 px-3">Inferred &rarr; Forecast Stage</th>
                <th className="py-2.5 px-3">Prob / Lead Time</th>
                <th className="py-2.5 px-3">Status Workflow</th>
                <th className="py-2.5 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredAlerts.length > 0 ? (
                filteredAlerts.map((alert) => {
                  const currentInfo = ATTACK_STAGE_INFO[alert.currentStage] || ATTACK_STAGE_INFO.BENIGN;
                  const nextInfo = ATTACK_STAGE_INFO[alert.predictedNextStage] || ATTACK_STAGE_INFO.BENIGN;

                  return (
                    <tr key={alert.id} className="hover:bg-slate-850/40 transition-colors">
                      <td className="py-2.5 px-3 font-bold text-slate-200">
                        {alert.id}
                        {alert.deduplicationCount > 1 && (
                          <span className="ml-1.5 px-1 py-0.2 rounded text-[9px] bg-slate-800 text-cyan-400 border border-slate-700">
                            x{alert.deduplicationCount}
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(alert.severity)}`}>
                          {alert.severity}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                        {alert.timestamp}
                      </td>
                      <td className="py-2.5 px-3 text-slate-300">
                        <span className="text-amber-400 font-semibold">{alert.sourceIp}</span> &rarr;{' '}
                        <span className="text-slate-200">{alert.destinationIp}</span>
                        <span className="text-slate-500 text-[10px] ml-1">({alert.dstPortSummary})</span>
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="flex items-center space-x-1.5">
                          <span className="font-semibold" style={{ color: currentInfo.color }}>
                            {alert.currentStage.replace(/_/g, ' ')}
                          </span>
                          <span className="text-slate-500">&rarr;</span>
                          <span className="font-semibold text-cyan-400" style={{ color: nextInfo.color }}>
                            {alert.predictedNextStage.replace(/_/g, ' ')}
                          </span>
                        </div>
                      </td>
                      <td className="py-2.5 px-3">
                        <div className="text-slate-100 font-bold">
                          {(alert.attackProbability * 100).toFixed(0)}%
                        </div>
                        <div className="text-[10px] text-emerald-400">
                          +{alert.earlyWarningSeconds}s lead
                        </div>
                      </td>
                      <td className="py-2.5 px-3">
                        <select
                          value={alert.status}
                          onChange={(e) => onUpdateAlertStatus(alert.id, e.target.value as AlertStatus)}
                          className={`text-[10px] rounded px-2 py-1 font-bold border focus:outline-none ${getStatusBadge(alert.status)}`}
                        >
                          <option value="NEW">NEW</option>
                          <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
                          <option value="INVESTIGATING">INVESTIGATING</option>
                          <option value="RESOLVED">RESOLVED</option>
                          <option value="FALSE_POSITIVE">FALSE POSITIVE</option>
                        </select>
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <button
                          onClick={() => onSelectAlertForInvestigation(alert)}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-slate-700 text-[11px] font-semibold flex items-center space-x-1 ml-auto"
                        >
                          <FileSearch className="w-3 h-3" />
                          <span>Investigate</span>
                        </button>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 font-mono">
                    No alerts matching current filter parameters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
