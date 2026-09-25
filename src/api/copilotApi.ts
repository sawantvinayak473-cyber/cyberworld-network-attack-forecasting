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

interface GeminiGenerateContentResponse {
  candidates?: Array<{
    content?: {
      parts?: Array<{
        text?: string;
      }>;
    };
  }>;
}

const FILTER_TRANSLATOR_SYSTEM_PROMPT = `You are a filter translator. Convert the user's natural language query into a JSON AlertFilter object. Use ONLY these fields:
severity (array of: LOW, MEDIUM, HIGH, CRITICAL),
status (array of: NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE),
stage (array of: BENIGN, RECONNAISSANCE, INITIAL_ACCESS, LATERAL_MOVEMENT, COMMAND_AND_CONTROL, EXFILTRATION),
sourceIp (string, exact IP),
minProbability (number 0-1).
Return ONLY valid JSON. No explanation, no markdown, no preamble.`;

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

const UNAVAILABLE_MESSAGE = 'This information is not available in the current telemetry.';
const MAX_RESPONSE_WORDS = 200;
const GEMINI_REQUEST_TIMEOUT_MS = 10_000;
const GEMINI_MODEL = 'gemini-flash-lite-latest';

async function generateGeminiContent(apiKey: string, prompt: string, maxOutputTokens: number): Promise<GeminiGenerateContentResponse> {
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), GEMINI_REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      signal: controller.signal,
      body: JSON.stringify({
        contents: [{ role: 'user', parts: [{ text: prompt }] }],
        generationConfig: { maxOutputTokens },
      }),
    });

    if (!response.ok) {
      throw new Error(`Gemini request failed (${response.status})`);
    }
    return response.json() as Promise<GeminiGenerateContentResponse>;
  } finally {
    window.clearTimeout(timeoutId);
  }
}

function isExactIpv4(value: string): boolean {
  const octets = value.split('.');
  return octets.length === 4 && octets.every((octet) => {
    if (!/^\d{1,3}$/.test(octet)) return false;
    const numericOctet = Number(octet);
    return numericOctet >= 0 && numericOctet <= 255;
  });
}

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
  const apiKey = import.meta.env.VITE_GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error('Missing VITE_GEMINI_API_KEY');
  }

  const payload = await generateGeminiContent(apiKey, `${FILTER_TRANSLATOR_SYSTEM_PROMPT}\n\n${query}`, 180);
  const json = payload.candidates?.[0]?.content?.parts?.[0]?.text?.trim();

  if (!json) {
    throw new Error('The query translator returned no filter.');
  }

  try {
    return sanitizeAlertFilter(JSON.parse(json));
  } catch {
    throw new Error('The query translator returned invalid JSON.');
  }
}

function buildSystemPrompt(context: CopilotContext): string {
  return `You are CyberWorld SOC Copilot, an AI assistant embedded in a predictive network security platform. You have access ONLY to the structured data provided below from the CyberWorld inference engine.

STRICT RULES:
1. Answer ONLY from the provided context data. Never invent facts.
2. Never generate IP addresses, port numbers, MITRE IDs, or probabilities not in the context.
3. If asked about something not in the context, respond: '${UNAVAILABLE_MESSAGE}'
4. Keep responses concise and analyst-oriented (max 200 words).
5. Format investigation plans as numbered steps.
6. For executive summaries, write 2-3 plain-language sentences.
7. Never recommend executing commands autonomously — always frame as 'the analyst should.'

CURRENT INCIDENT CONTEXT:
${JSON.stringify(context, null, 2)}

Answer the analyst's question using ONLY the above context.`;
}

function exceedsGroundingGuardrails(response: string, context: CopilotContext): boolean {
  if (response.trim().split(/\s+/).filter(Boolean).length > MAX_RESPONSE_WORDS) return true;

  const allowedIps = new Set([context.sourceIp, context.destinationIp].filter(Boolean));
  const responseIps = response.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
  if (responseIps.some((ip) => !allowedIps.has(ip))) return true;

  const allowedMitreIds = new Set(context.mitreCandidates.map((candidate) => candidate.id.toUpperCase()));
  const responseMitreIds = response.match(/\bT\d{4}(?:\.\d{3})?\b/gi) || [];
  if (responseMitreIds.some((id) => !allowedMitreIds.has(id.toUpperCase()))) return true;

  // No ports are supplied in CopilotContext, so any mentioned port is ungrounded.
  if (/\bports?\s*(?:number\s*)?\d+\b/i.test(response)) return true;

  const allowedPercentages = [
    context.attackProbability * 100,
    ...context.forecasts.map((forecast) => forecast.attackProbability * 100),
    ...context.mitreCandidates.map((candidate) => candidate.confidence * 100),
  ];
  const responsePercentages = response.match(/\b\d+(?:\.\d+)?%/g) || [];
  if (responsePercentages.some((percentage) => {
    const value = Number(percentage.slice(0, -1));
    return !allowedPercentages.some((allowed) => Math.abs(allowed - value) < 0.11);
  })) return true;

  const allowedDecimalProbabilities = [
    context.attackProbability,
    ...context.forecasts.map((forecast) => forecast.attackProbability),
    ...context.mitreCandidates.map((candidate) => candidate.confidence),
    context.residualAnomaly.residualScore,
    ...context.residualAnomaly.surprisedFeatures.flatMap((feature) => [
      feature.predicted,
      feature.actual,
      feature.deviation,
    ]),
  ];
  const responseDecimalProbabilities = response.match(/\b(?:0\.\d+|1\.0+)\b/g) || [];
  if (responseDecimalProbabilities.some((probability) => {
    const value = Number(probability);
    return !allowedDecimalProbabilities.some((allowed) => Math.abs(allowed - value) < 0.001);
  })) return true;

  return false;
}

export async function askCopilot(
  question: string,
  context: CopilotContext,
): Promise<string> {
  const apiKey = import.meta.env.VITE_GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error('Missing VITE_GEMINI_API_KEY');
  }

  const systemPrompt = buildSystemPrompt(context);
  const payload = await generateGeminiContent(apiKey, `${systemPrompt}\n\n${question}`, 250);
  const answer = payload.candidates?.[0]?.content?.parts?.[0]?.text?.trim();

  if (!answer || exceedsGroundingGuardrails(answer, context)) {
    return UNAVAILABLE_MESSAGE;
  }

  return answer;
}
