import type { Alert, AlertSeverity } from '../types';

const CASE_STORAGE_KEY = 'cyberworld-cases';

export type SOCCaseStatus = 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'CLOSED';
export type CaseEventType = 'ALERT_LINKED' | 'STATUS_CHANGE' | 'ANALYST_NOTE' | 'ACTION_TAKEN' | 'AI_ASSESSMENT';

export interface CaseEvent {
  eventId: string;
  timestamp: string;
  eventType: CaseEventType;
  description: string;
  analyst: string;
}

export interface SOCCase {
  caseId: string;
  incidentId: string;
  title: string;
  severity: AlertSeverity;
  status: SOCCaseStatus;
  owner: string;
  createdAt: string;
  updatedAt: string;
  linkedAlertIds: string[];
  mitreMapping: string[];
  aiSummary: string;
  timeline: CaseEvent[];
  resolutionNotes: string;
}

function now(): string {
  return new Date().toISOString();
}

function unique(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}

function makeEventId(): string {
  return `EVT-${Date.now()}-${Math.random().toString(36).slice(2, 8).toUpperCase()}`;
}

function getStorage(): Storage | null {
  if (typeof window === 'undefined') return null;
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

function persistCases(cases: SOCCase[]): void {
  const storage = getStorage();
  if (!storage) return;
  try {
    storage.setItem(CASE_STORAGE_KEY, JSON.stringify(cases));
    window.dispatchEvent(new CustomEvent('cyberworld-cases-updated'));
  } catch {
    // Browser privacy mode or storage quota must not break SOC workflows.
  }
}

function nextCaseId(cases: SOCCase[]): string {
  const year = new Date().getUTCFullYear();
  const matcher = new RegExp(`^CASE-${year}-(\\d{3,})$`);
  const lastSequence = cases.reduce((max, socCase) => {
    const match = socCase.caseId.match(matcher);
    return match ? Math.max(max, Number(match[1])) : max;
  }, 0);
  return `CASE-${year}-${String(lastSequence + 1).padStart(3, '0')}`;
}

function updateCase(
  caseId: string,
  updater: (socCase: SOCCase) => SOCCase,
): SOCCase | null {
  const cases = getAllCases();
  const index = cases.findIndex((socCase) => socCase.caseId === caseId);
  if (index < 0) return null;

  const updatedCase = updater(cases[index]);
  cases[index] = updatedCase;
  persistCases(cases);
  return updatedCase;
}

export function getAllCases(): SOCCase[] {
  const storage = getStorage();
  if (!storage) return [];
  try {
    const parsed = JSON.parse(storage.getItem(CASE_STORAGE_KEY) || '[]');
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((item): item is SOCCase => (
      item
      && typeof item.caseId === 'string'
      && typeof item.title === 'string'
      && Array.isArray(item.linkedAlertIds)
      && Array.isArray(item.timeline)
    ));
  } catch {
    return [];
  }
}

export function getCaseById(caseId: string): SOCCase | null {
  return getAllCases().find((socCase) => socCase.caseId === caseId) || null;
}

export function createCase(alert: Alert): SOCCase {
  const cases = getAllCases();
  const existing = cases.find((socCase) => socCase.linkedAlertIds.includes(alert.id));
  if (existing) return existing;

  const timestamp = now();
  const socCase: SOCCase = {
    caseId: nextCaseId(cases),
    incidentId: alert.incidentId,
    title: `${alert.severity} ${alert.currentStage.replace(/_/g, ' ')} alert — ${alert.sourceIp} → ${alert.destinationIp}`,
    severity: alert.severity,
    status: 'OPEN',
    owner: 'Unassigned',
    createdAt: timestamp,
    updatedAt: timestamp,
    linkedAlertIds: [alert.id],
    mitreMapping: unique(alert.mitreCandidates.map((candidate) => candidate.id)),
    aiSummary: '',
    timeline: [{
      eventId: makeEventId(),
      timestamp,
      eventType: 'ALERT_LINKED',
      description: `Alert ${alert.id} was linked when this case was created.`,
      analyst: 'System',
    }],
    resolutionNotes: '',
  };
  persistCases([...cases, socCase]);
  return socCase;
}

export function createManualCase(
  title = 'Manual SOC Case',
  severity: AlertSeverity = 'MEDIUM',
  owner = 'Unassigned',
): SOCCase {
  const cases = getAllCases();
  const timestamp = now();
  const socCase: SOCCase = {
    caseId: nextCaseId(cases),
    incidentId: `INC-MANUAL-${Date.now()}`,
    title,
    severity,
    status: 'OPEN',
    owner,
    createdAt: timestamp,
    updatedAt: timestamp,
    linkedAlertIds: [],
    mitreMapping: [],
    aiSummary: '',
    timeline: [{
      eventId: makeEventId(),
      timestamp,
      eventType: 'ANALYST_NOTE',
      description: 'Manual SOC case created.',
      analyst: owner,
    }],
    resolutionNotes: '',
  };
  persistCases([...cases, socCase]);
  return socCase;
}

export function updateCaseStatus(
  caseId: string,
  status: SOCCaseStatus,
  analyst: string,
): SOCCase | null {
  return updateCase(caseId, (socCase) => {
    if (socCase.status === status) return socCase;
    const timestamp = now();
    return {
      ...socCase,
      status,
      updatedAt: timestamp,
      timeline: [...socCase.timeline, {
        eventId: makeEventId(),
        timestamp,
        eventType: 'STATUS_CHANGE',
        description: `Case status changed from ${socCase.status} to ${status}.`,
        analyst: analyst.trim() || 'Analyst',
      }],
    };
  });
}

export function addCaseEvent(
  caseId: string,
  event: Omit<CaseEvent, 'eventId' | 'timestamp'> & Partial<Pick<CaseEvent, 'eventId' | 'timestamp'>>,
): SOCCase | null {
  return updateCase(caseId, (socCase) => {
    const timestamp = event.timestamp || now();
    return {
      ...socCase,
      updatedAt: timestamp,
      timeline: [...socCase.timeline, {
        ...event,
        eventId: event.eventId || makeEventId(),
        timestamp,
        analyst: event.analyst.trim() || 'Analyst',
      }],
    };
  });
}

export function linkAlert(caseId: string, alertId: string): SOCCase | null {
  return updateCase(caseId, (socCase) => {
    if (socCase.linkedAlertIds.includes(alertId)) return socCase;
    const timestamp = now();
    return {
      ...socCase,
      updatedAt: timestamp,
      linkedAlertIds: [...socCase.linkedAlertIds, alertId],
      timeline: [...socCase.timeline, {
        eventId: makeEventId(),
        timestamp,
        eventType: 'ALERT_LINKED',
        description: `Alert ${alertId} was linked to this case.`,
        analyst: 'Analyst',
      }],
    };
  });
}

export function updateResolutionNotes(caseId: string, notes: string): SOCCase | null {
  return updateCase(caseId, (socCase) => ({
    ...socCase,
    resolutionNotes: notes,
    updatedAt: now(),
  }));
}

export function updateCaseOwner(caseId: string, owner: string): SOCCase | null {
  return updateCase(caseId, (socCase) => ({
    ...socCase,
    owner: owner.trim() || 'Unassigned',
    updatedAt: now(),
  }));
}

export function updateCaseAiSummary(caseId: string, aiSummary: string): SOCCase | null {
  return updateCase(caseId, (socCase) => {
    const timestamp = now();
    return {
      ...socCase,
      aiSummary,
      updatedAt: timestamp,
      timeline: [...socCase.timeline, {
        eventId: makeEventId(),
        timestamp,
        eventType: 'AI_ASSESSMENT',
        description: 'AI case assessment was generated from the available case context.',
        analyst: 'SOC Copilot',
      }],
    };
  });
}

export function exportCaseAsJson(caseId: string): string {
  const socCase = getCaseById(caseId);
  if (!socCase) return '';
  return JSON.stringify(socCase, null, 2);
}
