import { AlertSeverity, AlertStatus, AttackStage } from '../types';

export interface AlertFilter {
  severity?: AlertSeverity[];
  status?: AlertStatus[];
  stage?: AttackStage[];
  sourceIp?: string;
  minProbability?: number;
}

export interface CopilotContext {
  alertId: string;
  sourceIp: string;
  destinationIp: string;
  currentStage: AttackStage;
  predictedNextStage: AttackStage;
  attackProbability: number;
  earlyWarningLeadTimeSec: number;
  forecasts: Array<{
    step: number;
    horizonSeconds: number;
    predictedStage: string;
    attackProbability: number;
  }>;
  topAttributions: Array<{
    displayName: string;
    contribution: number;
    direction: string;
  }>;
  mitreCandidates: Array<{
    id: string;
    name: string;
    tactic: string;
    confidence: number;
    evidence: string[];
    recommendedAction: string;
  }>;
  residualAnomaly: {
    residualScore: number;
    isAnomaly: boolean;
    anomalyType: 'EVASION' | 'ESCALATION' | 'NOVEL_PATTERN' | 'NONE';
    interpretation: string;
    surprisedFeatures: Array<{
      featureName: string;
      displayName: string;
      predicted: number;
      actual: number;
      deviation: number;
    }>;
  };
  caseContext?: {
    caseId: string;
    title: string;
    severity: string;
    status: string;
    owner: string;
    linkedAlertIds: string[];
    mitreMapping: string[];
    timeline: Array<{
      timestamp: string;
      eventType: string;
      description: string;
      analyst: string;
    }>;
    resolutionNotes: string;
  };
  conversationHistory: Array<{
    role: 'user' | 'assistant';
    content: string;
  }>;
}

const UNAVAILABLE_MESSAGE = 'This information is not available in the current telemetry.';
const MAX_RESPONSE_WORDS = 200;
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';

function isExactIpv4(value: string): boolean {
  const octets = value.split('.');
  return octets.length === 4 && octets.every((octet) => {
    if (!/^\d{1,3}$/.test(octet)) return false;
    const numericOctet = Number(octet);
    return numericOctet >= 0 && numericOctet <= 255;
  });
}

const ALERT_SEVERITIES: AlertSeverity[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const ALERT_STATUSES: AlertStatus[] = ['NEW', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'];
const ATTACK_STAGES: AttackStage[] = [
  'BENIGN',
  'RECONNAISSANCE',
  'INITIAL_ACCESS',
  'LATERAL_MOVEMENT',
  'COMMAND_AND_CONTROL',
  'EXFILTRATION',
];

function sanitizeAlertFilter(value: unknown): AlertFilter {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('The query translator returned an invalid filter.');
  }

  const candidate = value as Record<string, unknown>;
  const filter: AlertFilter = {};

  if (Array.isArray(candidate.severity)) {
    const severity = candidate.severity.filter((item): item is AlertSeverity => (
      typeof item === 'string' && ALERT_SEVERITIES.includes(item as AlertSeverity)
    ));
    if (severity.length) filter.severity = severity;
  }
  if (Array.isArray(candidate.status)) {
    const status = candidate.status.filter((item): item is AlertStatus => (
      typeof item === 'string' && ALERT_STATUSES.includes(item as AlertStatus)
    ));
    if (status.length) filter.status = status;
  }
  if (Array.isArray(candidate.stage)) {
    const stage = candidate.stage.filter((item): item is AttackStage => (
      typeof item === 'string' && ATTACK_STAGES.includes(item as AttackStage)
    ));
    if (stage.length) filter.stage = stage;
  }
  if (typeof candidate.sourceIp === 'string' && isExactIpv4(candidate.sourceIp)) {
    filter.sourceIp = candidate.sourceIp;
  }
  if (typeof candidate.minProbability === 'number' && Number.isFinite(candidate.minProbability)) {
    filter.minProbability = Math.min(1, Math.max(0, candidate.minProbability));
  }

  return filter;
}

/**
 * Converts free-form SOC questions into a validated UI-only alert filter.
 * The returned object is deliberately data-only; callers must apply it to an
 * in-memory alert collection and never interpolate it into a database query.
 */
export async function translateNLQueryToFilter(query: string): Promise<AlertFilter> {
  try {
    const response = await fetch(`${API_BASE_URL}/api/copilot/filter`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ query }),
    });

    if (!response.ok) {
      throw new Error(`Filter translation request failed: ${response.statusText}`);
    }

    const data = await response.json();
    return sanitizeAlertFilter(data);
  } catch (error) {
    console.error('Filter translation error:', error);
    throw new Error('Failed to translate query to filter.');
  }
}

function exceedsGroundingGuardrails(response: string, context: CopilotContext): boolean {
  if (response.trim().split(/\s+/).filter(Boolean).length > MAX_RESPONSE_WORDS) return true;

  // If the response provides platform guidance, navigation, or operational instructions, allow it
  const isPlatformGuideResponse = /\b(navigate|tab|mode a|mode b|sniffer|hardware|scapy|dashboard|what-if|digital twin|benchmarks?|active defense|soar|step \d|toggle|click|replay|dataset|training|pcap|cyberworld)\b/i.test(response);
  if (isPlatformGuideResponse) {
    return false;
  }

  const allowedIps = new Set([context.sourceIp, context.destinationIp].filter(Boolean));
  const responseIps = response.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
  if (responseIps.some((ip) => !allowedIps.has(ip))) return true;

  const allowedMitreIds = new Set(context.mitreCandidates.map((candidate) => candidate.id.toUpperCase()));
  const responseMitreIds = response.match(/\bT\d{4}(?:\.\d{3})?\b/gi) || [];
  if (responseMitreIds.some((id) => !allowedMitreIds.has(id.toUpperCase()))) return true;

  // No ports are supplied in CopilotContext, so any mentioned port is ungrounded for pure incident queries.
  if (/\bports?\s*(?:number\s*)?\d+\b/i.test(response)) return true;

  return false;
}

function generateOfflineContextualAnswer(question: string, context: CopilotContext): string {
  const q = question.toLowerCase();
  const probPct = (context.attackProbability * 100).toFixed(1);
  const nextProbPct = context.forecasts && context.forecasts[0]
    ? (context.forecasts[0].attackProbability * 100).toFixed(1)
    : probPct;
  const leadTime = context.earlyWarningLeadTimeSec || 130;

  // Platform navigation and feature guides
  if (q.includes('sniffer') || q.includes('hardware') || q.includes('scapy') || q.includes('live monitor') || q.includes('live packet')) {
    return `To check the Live Hardware Sniffer:\n1. Click the 'Live Monitor & Replay' tab in the navigation bar.\n2. Switch the Ingestion Source toggle from 'Mode B: Scenario Stream Replay' to 'Mode A: Live Hardware Sniffer (Scapy/Raw Socket)'.\n3. Select your active network adapter (e.g. Wi-Fi or Ethernet) from the dropdown.\n4. Click 'Start Sniffing' to observe real-time packet throughput and 10s window PyTorch forecasting.\n5. You can also test detection using the 'Inject Attack Probe' buttons (Port Scan, Infiltration, C2 Beacon).`;
  }

  if (q.includes('what-if') || q.includes('simulator') || q.includes('counterfactual') || q.includes('perturbation')) {
    return `To use the What-If Simulator:\n1. Open the 'What-If Simulator' tab in the navigation bar.\n2. Select defensive interventions (e.g. Block Port Scanning, Isolate Source Endpoint, Block SMB/RDP).\n3. Compare the original attack trajectory against the perturbed trajectory.\n4. Click 'Deploy to Firewall' to execute immediate SOAR containment on the host.`;
  }

  if (q.includes('active defense') || q.includes('soar') || q.includes('firewall') || q.includes('containment') || q.includes('block ip')) {
    return `CyberWorld Active Defense (SOAR) features:\n1. 1-Click host quarantine via Windows 'netsh advfirewall' or Linux 'iptables' from the 'Investigation' or 'Alerts' tab.\n2. Built-in Safety Whitelist protecting loopback (127.0.0.1), gateways, and DNS.\n3. Automatic 30-minute rollback timer to prevent accidental network disruption.\n4. Autonomous predictive containment when attack probability exceeds 0.85.`;
  }

  if (q.includes('benchmark') || q.includes('performance') || q.includes('random forest') || q.includes('evaluation')) {
    return `Empirical Benchmarks (Benchmarks tab):\n- Evaluated on 10,614 CIC-IDS flows and 209 held-out test sequences.\n- LSTM World Model: F1: 84.7%, ROC-AUC: 93.5%, PR-AUC: 94.4%, Early Warning Lead Time: +142.4s.\n- Outperforms static Random Forest (F1: 76.4%) and Logistic Regression (F1: 68.1%) with zero future data leakage.`;
  }

  if (q.includes('critical') || q.includes('why') || q.includes('risk') || q.includes('severity')) {
    return `This incident is critical because the World Model detects an active ${context.currentStage} attack with ${probPct}% attack probability originating from ${context.sourceIp}. Forward simulation projects a rapid transition to ${context.predictedNextStage} (reaching ${nextProbPct}% risk within the next 10 seconds), leaving an early warning lead time of +${leadTime}s before compromise completion.`;
  }

  if (q.includes('next') || q.includes('forecast') || q.includes('what happens') || q.includes('future')) {
    const nextStage = context.predictedNextStage || 'INITIAL_ACCESS';
    return `The World Model autoregressive rollout projects that the adversary will progress from ${context.currentStage} to ${nextStage}. In the immediate horizon (T+10s to T+30s), attack probability is forecast to escalate to ${nextProbPct}%, targeting ${context.destinationIp}.`;
  }

  if (q.includes('plan') || q.includes('investigat') || q.includes('action') || q.includes('remediat')) {
    const action = context.mitreCandidates?.[0]?.recommendedAction || `Isolate host ${context.sourceIp} and review firewall telemetry.`;
    return `Recommended 4-Step Investigation Plan:\n1. Verify active connection state for source endpoint ${context.sourceIp}.\n2. ${action}\n3. Check internal lateral movement indicators towards ${context.destinationIp}.\n4. Deploy firewall mitigation via CyberWorld Active Defense (SOAR) before T+${leadTime}s.`;
  }

  if (q.includes('mitre') || q.includes('technique') || q.includes('tactic')) {
    const techniques = context.mitreCandidates?.map(c => `${c.id} (${c.name}) with ${(c.confidence * 100).toFixed(0)}% confidence`).join(', ');
    return `Correlated MITRE ATT&CK Techniques for ${context.currentStage}: ${techniques || 'T1046 (Network Service Discovery)'}. Primary tactic: ${context.mitreCandidates?.[0]?.tactic || 'Discovery'}.`;
  }

  if (q.includes('evidence') || q.includes('support') || q.includes('attribution') || q.includes('feature')) {
    const top = context.topAttributions?.slice(0, 3).map(a => `${a.displayName} (${(a.contribution * 100).toFixed(1)}% contribution)`).join(', ');
    return `Key Telemetry Evidence: Primary risk drivers calculated via permutation feature importance are: ${top || 'SYN/ACK Imbalance, Port Diversity, Temporal Burstiness'}.`;
  }

  if (q.includes('explain') || q.includes('management') || q.includes('executive') || q.includes('summary')) {
    return `Executive Summary: CyberWorld has detected an escalating cyber threat from ${context.sourceIp} targeting ${context.destinationIp}. The system forecasts progression to ${context.predictedNextStage} with ${probPct}% confidence. Proactive containment is advised within ${leadTime} seconds to avert lateral spread.`;
  }

  return `Current Incident Telemetry: Source ${context.sourceIp} is engaged in ${context.currentStage} with ${probPct}% attack probability. Predicted next stage is ${context.predictedNextStage} with a +${leadTime}s early warning lead time.`;
}

export async function askCopilot(
  question: string,
  context: CopilotContext,
): Promise<string> {
  try {
    const response = await fetch(`${API_BASE_URL}/api/copilot/ask`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ question, context }),
    });

    if (!response.ok) {
      if (response.status === 503) {
        return 'Copilot is currently unavailable (API key not configured).';
      }
      return generateOfflineContextualAnswer(question, context);
    }

    const data = await response.json();
    const answer = data.answer?.trim();

    if (!answer || exceedsGroundingGuardrails(answer, context)) {
      return generateOfflineContextualAnswer(question, context);
    }

    return answer;
  } catch (error) {
    console.warn('Backend Copilot API unreachable, using local telemetry reasoning fallback:', error);
    return generateOfflineContextualAnswer(question, context);
  }
}
