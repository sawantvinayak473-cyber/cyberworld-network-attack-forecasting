import React, { useEffect, useMemo, useState } from 'react';
import {
  Bot,
  ClipboardList,
  Download,
  ExternalLink,
  FileText,
  Link2,
  MessageSquarePlus,
  Plus,
  Sparkles,
  UserRound,
} from 'lucide-react';
import type { Alert, AlertSeverity } from '../types';
import type { CopilotContext } from '../api/copilotApi';
import { askCopilot } from '../api/copilotApi';
import {
  addCaseEvent,
  createManualCase,
  exportCaseAsJson,
  updateCaseAiSummary,
  updateCaseOwner,
  updateCaseStatus,
  updateResolutionNotes,
} from '../engine/caseStorage';
import type { SOCCase, SOCCaseStatus } from '../engine/caseStorage';

type CaseTab = 'overview' | 'timeline' | 'evidence' | 'ai-summary';

interface CaseManagementViewProps {
  cases: SOCCase[];
  alerts: Alert[];
  copilotContext: Omit<CopilotContext, 'conversationHistory'>;
  onCasesChanged: () => void;
  onOpenInvestigation: (alert: Alert) => void;
}

const CASE_STATUSES: Array<'ALL' | SOCCaseStatus> = ['ALL', 'OPEN', 'INVESTIGATING', 'CONTAINED', 'CLOSED'];

function severityClass(severity: AlertSeverity): string {
  if (severity === 'CRITICAL') return 'border-red-700 bg-red-950/60 text-red-300';
  if (severity === 'HIGH') return 'border-orange-700 bg-orange-950/60 text-orange-300';
  if (severity === 'MEDIUM') return 'border-amber-700 bg-amber-950/60 text-amber-300';
  return 'border-blue-700 bg-blue-950/60 text-blue-300';
}

function statusClass(status: SOCCaseStatus): string {
  if (status === 'OPEN') return 'border-cyan-700 bg-cyan-950/60 text-cyan-300';
  if (status === 'INVESTIGATING') return 'border-amber-700 bg-amber-950/60 text-amber-300';
  if (status === 'CONTAINED') return 'border-emerald-700 bg-emerald-950/60 text-emerald-300';
  return 'border-slate-600 bg-slate-800 text-slate-300';
}

function readableTimestamp(timestamp: string): string {
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime()) ? timestamp : date.toLocaleString();
}

export const CaseManagementView: React.FC<CaseManagementViewProps> = ({
  cases,
  alerts,
  copilotContext,
  onCasesChanged,
  onOpenInvestigation,
}) => {
  const [statusFilter, setStatusFilter] = useState<'ALL' | SOCCaseStatus>('ALL');
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<CaseTab>('overview');
  const [ownerDraft, setOwnerDraft] = useState('');
  const [resolutionDraft, setResolutionDraft] = useState('');
  const [manualNote, setManualNote] = useState('');
  const [isGeneratingSummary, setIsGeneratingSummary] = useState(false);
  const [summaryError, setSummaryError] = useState(false);

  const visibleCases = useMemo(
    () => cases.filter((socCase) => statusFilter === 'ALL' || socCase.status === statusFilter),
    [cases, statusFilter],
  );
  const selectedCase = cases.find((socCase) => socCase.caseId === selectedCaseId) || null;
  const linkedAlerts = selectedCase
    ? selectedCase.linkedAlertIds.map((alertId) => alerts.find((alert) => alert.id === alertId) || null)
    : [];

  useEffect(() => {
    if (!selectedCaseId || !cases.some((socCase) => socCase.caseId === selectedCaseId)) {
      setSelectedCaseId(cases[0]?.caseId || null);
    }
  }, [cases, selectedCaseId]);

  useEffect(() => {
    if (!selectedCase) return;
    setOwnerDraft(selectedCase.owner);
    setResolutionDraft(selectedCase.resolutionNotes);
    setManualNote('');
    setSummaryError(false);
  }, [selectedCase?.caseId, selectedCase?.owner, selectedCase?.resolutionNotes]);

  const handleCreateManualCase = () => {
    const newCase = createManualCase();
    onCasesChanged();
    setSelectedCaseId(newCase.caseId);
    setActiveTab('overview');
  };

  const handleStatusChange = (status: SOCCaseStatus) => {
    if (!selectedCase) return;
    updateCaseStatus(selectedCase.caseId, status, ownerDraft);
    onCasesChanged();
  };

  const handleSaveOverview = () => {
    if (!selectedCase) return;
    const notesChanged = resolutionDraft !== selectedCase.resolutionNotes;
    updateCaseOwner(selectedCase.caseId, ownerDraft);
    updateResolutionNotes(selectedCase.caseId, resolutionDraft);
    if (notesChanged) {
      addCaseEvent(selectedCase.caseId, {
        eventType: 'ANALYST_NOTE',
        description: 'Resolution notes were updated.',
        analyst: ownerDraft || 'Analyst',
      });
    }
    onCasesChanged();
  };

  const handleAddManualNote = () => {
    if (!selectedCase || !manualNote.trim()) return;
    addCaseEvent(selectedCase.caseId, {
      eventType: 'ANALYST_NOTE',
      description: manualNote.trim(),
      analyst: ownerDraft || 'Analyst',
    });
    setManualNote('');
    onCasesChanged();
  };

  const handleExport = () => {
    if (!selectedCase) return;
    const json = exportCaseAsJson(selectedCase.caseId);
    if (!json) return;
    const url = URL.createObjectURL(new Blob([json], { type: 'application/json' }));
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `${selectedCase.caseId}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const handleRegenerateSummary = async () => {
    if (!selectedCase || isGeneratingSummary) return;
    setIsGeneratingSummary(true);
    setSummaryError(false);
    try {
      const aiSummary = await askCopilot(
        'Write a concise analyst-oriented summary for this SOC case. Use only the provided incident telemetry and case context. State uncertainty when the case data does not establish a fact.',
        {
          ...copilotContext,
          caseContext: {
            caseId: selectedCase.caseId,
            title: selectedCase.title,
            severity: selectedCase.severity,
            status: selectedCase.status,
            owner: selectedCase.owner,
            linkedAlertIds: selectedCase.linkedAlertIds,
            mitreMapping: selectedCase.mitreMapping,
            timeline: selectedCase.timeline.map((event) => ({
              timestamp: event.timestamp,
              eventType: event.eventType,
              description: event.description,
              analyst: event.analyst,
            })),
            resolutionNotes: selectedCase.resolutionNotes,
          },
          conversationHistory: [],
        },
      );
      updateCaseAiSummary(selectedCase.caseId, aiSummary);
      onCasesChanged();
    } catch {
      setSummaryError(true);
    } finally {
      setIsGeneratingSummary(false);
    }
  };

  return (
    <section className="grid min-h-[650px] grid-cols-1 overflow-hidden rounded-xl border border-slate-800 bg-slate-900/55 shadow-sm xl:grid-cols-[340px_minmax(0,1fr)]">
      <aside className="border-b border-slate-800 bg-slate-950/35 xl:border-b-0 xl:border-r">
        <div className="border-b border-slate-800 p-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <p className="text-[10px] font-mono tracking-[0.18em] text-cyan-400">SOC CASE MANAGEMENT</p>
              <h2 className="mt-1 text-base font-bold text-slate-100">Persistent investigation cases</h2>
            </div>
            <ClipboardList className="h-5 w-5 shrink-0 text-emerald-400" />
          </div>
          <div className="mt-4 flex gap-2">
            <select
              value={statusFilter}
              onChange={(event) => setStatusFilter(event.target.value as 'ALL' | SOCCaseStatus)}
              className="min-w-0 flex-1 rounded-lg border border-slate-700 bg-slate-900 px-2.5 py-2 text-xs font-mono text-slate-200 focus:border-emerald-500 focus:outline-none"
              aria-label="Filter cases by status"
            >
              {CASE_STATUSES.map((status) => <option key={status} value={status}>{status === 'ALL' ? 'All statuses' : status}</option>)}
            </select>
            <button
              type="button"
              onClick={handleCreateManualCase}
              className="flex items-center gap-1.5 rounded-lg bg-emerald-600 px-2.5 py-2 text-xs font-bold text-white transition-colors hover:bg-emerald-500"
            >
              <Plus className="h-3.5 w-3.5" />
              <span className="hidden sm:inline xl:hidden 2xl:inline">Create Manual Case</span>
              <span className="sm:hidden xl:inline 2xl:hidden">Create</span>
            </button>
          </div>
        </div>

        <div className="max-h-[520px] space-y-2 overflow-y-auto p-3 xl:max-h-[calc(100vh-270px)]">
          {visibleCases.map((socCase) => (
            <button
              key={socCase.caseId}
              type="button"
              onClick={() => {
                setSelectedCaseId(socCase.caseId);
                setActiveTab('overview');
              }}
              className={`w-full rounded-lg border p-3 text-left transition-colors ${
                selectedCase?.caseId === socCase.caseId
                  ? 'border-emerald-600/70 bg-emerald-950/25'
                  : 'border-slate-800 bg-slate-900/50 hover:border-slate-700 hover:bg-slate-800/70'
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <span className="font-mono text-[11px] font-bold text-cyan-300">{socCase.caseId}</span>
                <span className={`rounded border px-1.5 py-0.5 text-[9px] font-mono font-bold ${severityClass(socCase.severity)}`}>{socCase.severity}</span>
              </div>
              <p className="mt-1 line-clamp-2 text-xs font-semibold text-slate-200">{socCase.title}</p>
              <div className="mt-2 flex items-center justify-between gap-2 text-[10px] font-mono">
                <span className={`rounded border px-1.5 py-0.5 ${statusClass(socCase.status)}`}>{socCase.status}</span>
                <span className="truncate text-slate-500">{socCase.owner}</span>
              </div>
              <div className="mt-2 text-[10px] font-mono text-slate-600">{readableTimestamp(socCase.createdAt)}</div>
            </button>
          ))}
          {visibleCases.length === 0 && (
            <div className="px-4 py-10 text-center text-xs text-slate-500">
              No cases match this filter. High and Critical alerts create cases automatically.
            </div>
          )}
        </div>
      </aside>

      <div className="min-w-0 p-4 sm:p-5">
        {!selectedCase ? (
          <div className="flex min-h-[460px] flex-col items-center justify-center text-center">
            <FileText className="h-10 w-10 text-slate-600" />
            <h3 className="mt-3 text-sm font-bold text-slate-300">No case selected</h3>
            <p className="mt-1 max-w-sm text-xs leading-5 text-slate-500">Create a manual case or wait for a High/Critical alert to create one automatically.</p>
          </div>
        ) : (
          <>
            <header className="flex flex-col gap-3 border-b border-slate-800 pb-4 sm:flex-row sm:items-start sm:justify-between">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs font-bold text-cyan-300">{selectedCase.caseId}</span>
                  <span className={`rounded border px-1.5 py-0.5 text-[10px] font-mono font-bold ${severityClass(selectedCase.severity)}`}>{selectedCase.severity}</span>
                </div>
                <h2 className="mt-1 text-lg font-bold text-slate-100">{selectedCase.title}</h2>
              </div>
              <label className="text-[10px] font-mono uppercase text-slate-500">
                Case status
                <select
                  value={selectedCase.status}
                  onChange={(event) => handleStatusChange(event.target.value as SOCCaseStatus)}
                  className={`mt-1 block rounded-lg border px-2.5 py-1.5 text-xs font-bold focus:outline-none ${statusClass(selectedCase.status)}`}
                >
                  {CASE_STATUSES.filter((status): status is SOCCaseStatus => status !== 'ALL').map((status) => <option key={status} value={status}>{status}</option>)}
                </select>
              </label>
            </header>

            <nav className="mt-4 flex gap-1 overflow-x-auto border-b border-slate-800 pb-2" aria-label="Case detail tabs">
              {([
                ['overview', 'Overview'],
                ['timeline', 'Timeline'],
                ['evidence', 'Evidence'],
                ['ai-summary', 'AI Summary'],
              ] as Array<[CaseTab, string]>).map(([tabId, label]) => (
                <button
                  key={tabId}
                  type="button"
                  onClick={() => setActiveTab(tabId)}
                  className={`whitespace-nowrap rounded-md px-3 py-1.5 text-xs font-mono transition-colors ${
                    activeTab === tabId ? 'bg-slate-800 text-emerald-400' : 'text-slate-500 hover:bg-slate-900 hover:text-slate-200'
                  }`}
                >
                  {label}
                </button>
              ))}
            </nav>

            {activeTab === 'overview' && (
              <div className="space-y-5 pt-5">
                <div className="grid gap-4 md:grid-cols-2">
                  <label className="text-xs font-mono text-slate-400">
                    <span className="mb-1.5 flex items-center gap-1.5"><UserRound className="h-3.5 w-3.5" /> Case owner</span>
                    <input
                      value={ownerDraft}
                      onChange={(event) => setOwnerDraft(event.target.value)}
                      className="w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 focus:border-emerald-500 focus:outline-none"
                      placeholder="Analyst name"
                    />
                  </label>
                  <div>
                    <p className="mb-1.5 text-xs font-mono text-slate-400">MITRE techniques involved</p>
                    <div className="flex min-h-10 flex-wrap items-center gap-1.5 rounded-lg border border-slate-800 bg-slate-950/50 px-3 py-2">
                      {selectedCase.mitreMapping.length > 0
                        ? selectedCase.mitreMapping.map((technique) => <span key={technique} className="rounded border border-amber-800 bg-amber-950/50 px-1.5 py-0.5 text-[10px] font-mono font-bold text-amber-300">{technique}</span>)
                        : <span className="text-xs text-slate-500">No techniques linked yet.</span>}
                    </div>
                  </div>
                </div>

                <div>
                  <p className="mb-2 text-xs font-mono text-slate-400">Linked alerts</p>
                  <div className="space-y-2">
                    {selectedCase.linkedAlertIds.map((alertId, index) => {
                      const alert = linkedAlerts[index];
                      return (
                        <div key={alertId} className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-800 bg-slate-950/50 px-3 py-2 text-xs">
                          <span className="font-mono text-cyan-300">{alertId}</span>
                          {alert ? (
                            <button type="button" onClick={() => onOpenInvestigation(alert)} className="flex items-center gap-1 text-emerald-400 hover:text-emerald-300">
                              Open Investigation <ExternalLink className="h-3 w-3" />
                            </button>
                          ) : <span className="text-slate-500">Alert not in current replay</span>}
                        </div>
                      );
                    })}
                    {selectedCase.linkedAlertIds.length === 0 && <p className="rounded-lg border border-dashed border-slate-700 p-3 text-xs text-slate-500">No alert evidence is linked to this manual case.</p>}
                  </div>
                </div>

                <label className="block text-xs font-mono text-slate-400">
                  <span className="mb-1.5 block">Resolution notes</span>
                  <textarea
                    rows={5}
                    value={resolutionDraft}
                    onChange={(event) => setResolutionDraft(event.target.value)}
                    placeholder="Record containment decisions, validation, and closure rationale…"
                    className="w-full rounded-lg border border-slate-700 bg-slate-950 p-3 text-sm text-slate-100 placeholder:text-slate-600 focus:border-emerald-500 focus:outline-none"
                  />
                </label>
                <button type="button" onClick={handleSaveOverview} className="rounded-lg bg-emerald-600 px-4 py-2 text-xs font-bold text-white transition-colors hover:bg-emerald-500">Save case details</button>
              </div>
            )}

            {activeTab === 'timeline' && (
              <div className="pt-5">
                <div className="relative max-h-[410px] overflow-y-auto pl-7 pr-1">
                  <div className="absolute bottom-3 left-[7px] top-3 w-px bg-slate-700" />
                  {[...selectedCase.timeline].sort((left, right) => right.timestamp.localeCompare(left.timestamp)).map((event) => (
                    <div key={event.eventId} className="relative mb-4 rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                      <span className="absolute -left-[25px] top-4 h-3.5 w-3.5 rounded-full border-2 border-[#090d16] bg-emerald-500" />
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="rounded border border-slate-700 bg-slate-800 px-1.5 py-0.5 text-[10px] font-mono text-cyan-300">{event.eventType.replace(/_/g, ' ')}</span>
                        <span className="text-[10px] font-mono text-slate-500">{readableTimestamp(event.timestamp)}</span>
                      </div>
                      <p className="mt-2 text-xs text-slate-200">{event.description}</p>
                      <p className="mt-1 text-[10px] font-mono text-slate-500">{event.analyst}</p>
                    </div>
                  ))}
                </div>
                <div className="mt-4 flex gap-2 border-t border-slate-800 pt-4">
                  <input
                    value={manualNote}
                    onChange={(event) => setManualNote(event.target.value)}
                    onKeyDown={(event) => { if (event.key === 'Enter') handleAddManualNote(); }}
                    placeholder="Add manual note to case timeline…"
                    className="min-w-0 flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-emerald-500 focus:outline-none"
                  />
                  <button type="button" onClick={handleAddManualNote} disabled={!manualNote.trim()} className="flex items-center gap-1.5 rounded-lg bg-slate-800 px-3 py-2 text-xs font-bold text-emerald-300 hover:bg-slate-700 disabled:cursor-not-allowed disabled:text-slate-600">
                    <MessageSquarePlus className="h-3.5 w-3.5" /> Add note
                  </button>
                </div>
              </div>
            )}

            {activeTab === 'evidence' && (
              <div className="space-y-3 pt-5">
                {selectedCase.linkedAlertIds.map((alertId, index) => {
                  const alert = linkedAlerts[index];
                  return (
                    <div key={alertId} className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                      <div>
                        <div className="flex items-center gap-2"><Link2 className="h-3.5 w-3.5 text-cyan-400" /><span className="font-mono text-xs font-bold text-cyan-300">{alertId}</span></div>
                        {alert ? <p className="mt-1 text-xs text-slate-400">{alert.currentStage.replace(/_/g, ' ')} → {alert.predictedNextStage.replace(/_/g, ' ')}</p> : <p className="mt-1 text-xs text-slate-500">Alert is not present in the current replay.</p>}
                      </div>
                      {alert && <span className={`rounded border px-2 py-0.5 text-[10px] font-mono font-bold ${severityClass(alert.severity)}`}>{alert.severity}</span>}
                    </div>
                  );
                })}
                {selectedCase.linkedAlertIds.length === 0 && <p className="rounded-lg border border-dashed border-slate-700 p-4 text-center text-xs text-slate-500">No linked alert evidence is stored for this case.</p>}
                <button type="button" onClick={handleExport} className="mt-2 flex items-center gap-2 rounded-lg border border-cyan-700 bg-cyan-950/40 px-3 py-2 text-xs font-bold text-cyan-300 hover:bg-cyan-950/70">
                  <Download className="h-3.5 w-3.5" /> Export case as JSON
                </button>
              </div>
            )}

            {activeTab === 'ai-summary' && (
              <div className="pt-5">
                <div className="rounded-lg border border-emerald-900/60 bg-emerald-950/15 p-4">
                  <div className="flex items-center gap-2 text-xs font-mono font-bold text-emerald-300"><Bot className="h-4 w-4" /> AI CASE SUMMARY</div>
                  <p className="mt-3 whitespace-pre-wrap text-sm leading-6 text-slate-200">
                    {selectedCase.aiSummary || 'No AI summary has been generated for this case.'}
                  </p>
                </div>
                {summaryError && <p className="mt-3 text-xs font-mono text-amber-400">Copilot unavailable — check API key in .env</p>}
                <button
                  type="button"
                  onClick={() => void handleRegenerateSummary()}
                  disabled={isGeneratingSummary}
                  className="mt-4 flex items-center gap-2 rounded-lg bg-emerald-600 px-3 py-2 text-xs font-bold text-white hover:bg-emerald-500 disabled:cursor-not-allowed disabled:bg-slate-700"
                >
                  <Sparkles className="h-3.5 w-3.5" /> {isGeneratingSummary ? 'Generating…' : 'Regenerate with Copilot'}
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </section>
  );
};
