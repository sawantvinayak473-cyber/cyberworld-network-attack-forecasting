import {
  AttackStage,
  FeatureAttribution,
  ForecastStep,
  NetworkStateVector,
  RiskLevel,
} from '../types';
import {
  computeConfidenceBounds,
  computeWorldModelInference,
  getRiskLevel,
} from '../engine/worldModelSimulator';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
const BACKEND_TIMEOUT_MS = 3_000;
const FALLBACK_SCENARIO_ID = 'full-killchain';

export interface WorldModelResponse {
  attackProbability: number;
  predictedStage: AttackStage;
  predictedNextStage: AttackStage;
  forecasts: ForecastStep[];
  attributions: FeatureAttribution[];
  earlyWarningLeadTime: number;
}

export interface ForecastResponse {
  forecasts: ForecastStep[];
  maxProjectedRisk: number;
  earlyWarningLeadTime: number;
  projectedTerminalStage: AttackStage;
}

export interface ExplainabilityResponse {
  attributions: FeatureAttribution[];
  temporalAttention: Array<{ timeStep: string; weight: number }>;
}

interface BackendForecast {
  step: number;
  horizon_seconds: number;
  predicted_stage: AttackStage;
  attack_probability: number;
  confidence: number;
  risk_level?: RiskLevel;
  predicted_state_summary?: {
    syn_ack_ratio?: number;
    port_diversity?: number;
    burstiness?: number;
    flow_count?: number;
  };
}

interface BackendAttribution {
  feature_key: string;
  display_name: string;
  category: FeatureAttribution['category'];
  value: number;
  contribution: number;
  direction: 'INCREASES_RISK' | 'DECREASES_RISK';
}

interface BackendFullInferenceResponse {
  attack_probability: number;
  predicted_stage: AttackStage;
  predicted_next_stage: AttackStage;
  forecasts: BackendForecast[];
  attributions: BackendAttribution[];
  early_warning_lead_time: number;
}

interface BackendForecastResponse {
  rollout_steps: BackendForecast[];
  max_projected_risk: number;
  early_warning_lead_time_seconds: number;
  projected_terminal_stage: AttackStage;
}

interface BackendExplainabilityResponse {
  attributions: BackendAttribution[];
  temporal_attention: Array<{ time_step: string; weight: number }>;
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), BACKEND_TIMEOUT_MS);

  try {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`CyberWorld API request failed (${response.status})`);
    }

    return response.json() as Promise<T>;
  } finally {
    clearTimeout(timeoutId);
  }
}

function latestState(sequence: NetworkStateVector[]): NetworkStateVector {
  const state = sequence[sequence.length - 1];
  if (!state) {
    throw new Error('A non-empty NetworkStateVector sequence is required for inference.');
  }
  return state;
}

function fallbackInference(sequence: NetworkStateVector[]) {
  latestState(sequence);
  return computeWorldModelInference(
    sequence.length - 1,
    sequence,
    FALLBACK_SCENARIO_ID,
  );
}

function toForecastStep(forecast: BackendForecast, state: NetworkStateVector): ForecastStep {
  const attackProbability = Number(forecast.attack_probability);
  const confidence = Number(forecast.confidence);
  return {
    step: forecast.step,
    horizonSeconds: forecast.horizon_seconds,
    predictedStage: forecast.predicted_stage,
    attackProbability,
    confidence,
    ...computeConfidenceBounds(attackProbability, confidence),
    riskLevel: forecast.risk_level || getRiskLevel(attackProbability),
    predictedStateSummary: {
      synAckRatio: Number(forecast.predicted_state_summary?.syn_ack_ratio ?? state.synAckRatio),
      portDiversity: Number(forecast.predicted_state_summary?.port_diversity ?? state.portDiversity),
      burstiness: Number(forecast.predicted_state_summary?.burstiness ?? state.burstiness),
      flowCount: Number(forecast.predicted_state_summary?.flow_count ?? state.flowCount),
    },
  };
}

function toFeatureAttribution(attribution: BackendAttribution): FeatureAttribution {
  const contribution = Number(attribution.contribution);
  const value = Number(attribution.value);
  const formattedValue = Number.isFinite(value) ? value.toFixed(2) : String(attribution.value);

  return {
    featureName: attribution.feature_key,
    displayName: attribution.display_name,
    value,
    formattedValue,
    contribution,
    direction: attribution.direction === 'INCREASES_RISK' ? 'RISK_INCREASE' : 'RISK_DECREASE',
    category: attribution.category,
  };
}

/**
 * Runs the complete server-side inference path. If the API is unavailable, the
 * existing deterministic simulator remains the offline/air-gapped fallback.
 */
export async function fetchPrediction(sequence: NetworkStateVector[]): Promise<WorldModelResponse> {
  try {
    const response = await postJson<BackendFullInferenceResponse>('/api/model/full-inference', {
      sequence,
      horizon_steps: 10,
    });
    const state = latestState(sequence);

    return {
      attackProbability: Number(response.attack_probability),
      predictedStage: response.predicted_stage,
      predictedNextStage: response.predicted_next_stage,
      forecasts: response.forecasts.map((forecast) => toForecastStep(forecast, state)),
      attributions: response.attributions.map(toFeatureAttribution),
      earlyWarningLeadTime: Number(response.early_warning_lead_time),
    };
  } catch {
    const fallback = fallbackInference(sequence);
    return {
      attackProbability: fallback.attackProbability,
      predictedStage: fallback.predictedCurrentStage,
      predictedNextStage: fallback.predictedNextStage,
      forecasts: fallback.forecasts,
      attributions: fallback.attributions,
      earlyWarningLeadTime: fallback.earlyWarningLeadTime,
    };
  }
}

export async function fetchForecast(
  sequence: NetworkStateVector[],
  horizon: number,
): Promise<ForecastResponse> {
  const normalizedHorizon = Number.isFinite(horizon) ? Math.floor(horizon) : 10;
  const safeHorizon = Math.max(1, Math.min(100, normalizedHorizon));

  try {
    const response = await postJson<BackendForecastResponse>('/api/model/forecast', {
      sequence,
      horizon_steps: safeHorizon,
    });
    const state = latestState(sequence);
    const forecasts = response.rollout_steps.map((forecast) => toForecastStep(forecast, state));

    return {
      forecasts,
      maxProjectedRisk: Number(response.max_projected_risk),
      earlyWarningLeadTime: Number(response.early_warning_lead_time_seconds),
      projectedTerminalStage: response.projected_terminal_stage,
    };
  } catch {
    const fallback = fallbackInference(sequence);
    const forecasts = fallback.forecasts.slice(0, safeHorizon);
    return {
      forecasts,
      maxProjectedRisk: Math.max(...forecasts.map((forecast) => forecast.attackProbability)),
      earlyWarningLeadTime: fallback.earlyWarningLeadTime,
      projectedTerminalStage: forecasts[forecasts.length - 1]?.predictedStage || fallback.predictedNextStage,
    };
  }
}

export async function fetchExplainability(
  sequence: NetworkStateVector[],
): Promise<ExplainabilityResponse> {
  try {
    const response = await postJson<BackendExplainabilityResponse>('/api/model/explain', {
      sequence,
    });

    return {
      attributions: response.attributions.map(toFeatureAttribution),
      temporalAttention: response.temporal_attention.map((item) => ({
        timeStep: item.time_step,
        weight: Number(item.weight),
      })),
    };
  } catch {
    const fallback = fallbackInference(sequence);
    return {
      attributions: fallback.attributions,
      temporalAttention: [],
    };
  }
}

// ============================================================================
// Live Network Packet Sniffer Client (Pillar 1)
// ============================================================================

export interface SnifferStatus {
  is_running: boolean;
  interface: string;
  packets_captured: number;
  bytes_captured: number;
  active_flows_in_window: number;
  uptime_seconds: number;
  window_duration_seconds: number;
  has_latest_frame: boolean;
  scapy_available: boolean;
}

export interface SnifferInterface {
  id: string;
  name: string;
}

export async function fetchSnifferStatus(): Promise<SnifferStatus> {
  const response = await fetch(`${API_BASE_URL}/api/sniffer/status`);
  if (!response.ok) {
    throw new Error('Failed to fetch sniffer status');
  }
  return response.json();
}

export async function fetchSnifferInterfaces(): Promise<SnifferInterface[]> {
  const response = await fetch(`${API_BASE_URL}/api/sniffer/interfaces`);
  if (!response.ok) {
    throw new Error('Failed to fetch sniffer interfaces');
  }
  const data = await response.json();
  return data.interfaces || [];
}

export async function startSniffer(interfaceName?: string, windowSeconds: number = 10): Promise<SnifferStatus> {
  const response = await fetch(`${API_BASE_URL}/api/sniffer/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ interface: interfaceName, window_seconds: windowSeconds }),
  });
  if (!response.ok) {
    throw new Error('Failed to start sniffer');
  }
  const data = await response.json();
  return data.sensor;
}

export async function stopSniffer(): Promise<SnifferStatus> {
  const response = await fetch(`${API_BASE_URL}/api/sniffer/stop`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  });
  if (!response.ok) {
    throw new Error('Failed to stop sniffer');
  }
  const data = await response.json();
  return data.sensor;
}

export async function fetchSnifferLatest(): Promise<any> {
  const response = await fetch(`${API_BASE_URL}/api/sniffer/latest`);
  if (!response.ok) {
    throw new Error('Failed to fetch latest sniffer telemetry');
  }
  return response.json();
}

export async function injectSnifferAttack(stage: string, count: number = 150): Promise<any> {
  const response = await fetch(`${API_BASE_URL}/api/sniffer/inject`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ stage, count }),
  });
  if (!response.ok) {
    throw new Error('Failed to inject attack signature');
  }
  return response.json();
}

// ============================================================================
// Closed-Loop Active Defense & SOAR Mitigation Client (Pillar 2)
// ============================================================================

export interface MitigationAction {
  action_id: string;
  target_ip: string;
  target_stage: string;
  action_type: string;
  command_executed: string;
  rollback_command: string;
  status: 'ACTIVE' | 'ROLLED_BACK' | 'EXPIRED' | 'SIMULATED' | 'SIMULATED_SAFE';
  applied_at: string;
  expires_at?: string;
  expiry_minutes?: number;
  execution_mode: string;
  analyst: string;
  alert_id?: string;
  notes?: string;
  output?: string;
}

export interface MitigationPolicy {
  policy_mode: 'MANUAL_APPROVAL' | 'AUTONOMOUS_PREDICTIVE';
  auto_contain_threshold: number;
  default_expiry_minutes: number;
  os_type: string;
}

export async function applyMitigation(params: {
  target_ip: string;
  target_stage?: string;
  action_type?: string;
  execution_mode?: string;
  expiry_minutes?: number;
  analyst?: string;
  alert_id?: string;
  notes?: string;
}): Promise<MitigationAction> {
  const response = await fetch(`${API_BASE_URL}/api/mitigation/apply`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      target_ip: params.target_ip,
      target_stage: params.target_stage || 'INITIAL_ACCESS',
      action_type: params.action_type || 'DROP_INGRESS',
      execution_mode: params.execution_mode || 'LIVE',
      expiry_minutes: params.expiry_minutes ?? 30,
      analyst: params.analyst || 'SOC-Analyst',
      alert_id: params.alert_id,
      notes: params.notes || '',
    }),
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: 'Failed to apply containment' }));
    throw new Error(err.detail || 'Failed to apply containment');
  }
  const data = await response.json();
  return data.mitigation;
}

export async function rollbackMitigation(actionId: string, reason?: string): Promise<any> {
  const response = await fetch(`${API_BASE_URL}/api/mitigation/rollback`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action_id: actionId, reason: reason || 'Analyst Manual Rollback' }),
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: 'Failed to rollback containment' }));
    throw new Error(err.detail || 'Failed to rollback containment');
  }
  return response.json();
}

export async function fetchActiveMitigations(): Promise<MitigationAction[]> {
  const response = await fetch(`${API_BASE_URL}/api/mitigation/active`);
  if (!response.ok) {
    throw new Error('Failed to fetch active mitigations');
  }
  const data = await response.json();
  return data.active_mitigations || [];
}

export async function fetchMitigationHistory(limit: number = 50): Promise<MitigationAction[]> {
  const response = await fetch(`${API_BASE_URL}/api/mitigation/history?limit=${limit}`);
  if (!response.ok) {
    throw new Error('Failed to fetch mitigation history');
  }
  const data = await response.json();
  return data.mitigation_history || [];
}

export async function fetchMitigationPolicy(): Promise<MitigationPolicy> {
  const response = await fetch(`${API_BASE_URL}/api/mitigation/policy`);
  if (!response.ok) {
    throw new Error('Failed to fetch mitigation policy');
  }
  return response.json();
}

export async function updateMitigationPolicy(policyMode: string, autoContainThreshold: number = 0.85): Promise<MitigationPolicy> {
  const response = await fetch(`${API_BASE_URL}/api/mitigation/policy`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ policy_mode: policyMode, auto_contain_threshold: autoContainThreshold }),
  });
  if (!response.ok) {
    throw new Error('Failed to update mitigation policy');
  }
  return response.json();
}

// ============================================================================
// Model Status, Benchmarks & Interactive Training APIs
// ============================================================================

export interface ModelStatusResponse {
  model_loaded: boolean;
  inference_mode: 'pytorch' | 'fallback';
  model_version: string;
  training_metadata: Record<string, any>;
  evaluation_metrics: Record<string, any>;
  model_config?: Record<string, any>;
}

export interface BenchmarksResponse {
  status: string;
  model_architecture: string;
  features_dimension: number;
  binary_metrics: {
    precision: number;
    recall: number;
    f1_score: number;
    roc_auc: number;
    pr_auc: number;
    false_positive_rate: number;
    false_negative_rate: number;
  };
  stage_metrics: Record<string, {
    precision: number;
    recall: number;
    'f1-score': number;
    support: number;
  }>;
  comparison_summary: Array<{
    modelName: string;
    f1Score: number;
    rocAuc: number;
    falsePositiveRate: number;
    earlyWarningLeadTimeSec: number;
    forecastAccuracyT1: number;
    forecastAccuracyT5: number;
    isWorldModel: boolean;
  }>;
  model_config?: Record<string, any>;
}

export async function fetchModelStatus(): Promise<ModelStatusResponse> {
  const response = await fetch(`${API_BASE_URL}/api/model/status`);
  if (!response.ok) {
    throw new Error('Failed to fetch model status');
  }
  return response.json();
}

export async function fetchBenchmarks(): Promise<BenchmarksResponse> {
  const response = await fetch(`${API_BASE_URL}/api/benchmarks`);
  if (!response.ok) {
    throw new Error('Failed to fetch benchmarks');
  }
  return response.json();
}

export async function triggerModelTraining(params?: {
  epochs?: number;
  batch_size?: number;
  learning_rate?: number;
  seq_len?: number;
}): Promise<any> {
  const response = await fetch(`${API_BASE_URL}/api/model/train`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(params || {}),
  });
  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: 'Failed to train model' }));
    throw new Error(err.detail || 'Failed to train model');
  }
  return response.json();
}

export async function forecastStateSequence(
  sequence: NetworkStateVector[],
  horizonSteps: number = 10
): Promise<ForecastStep[]> {
  const response = await fetch(`${API_BASE_URL}/api/model/forecast`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sequence, horizon_steps: horizonSteps }),
  });
  if (!response.ok) {
    throw new Error('Failed to compute model forecast');
  }
  const data = await response.json();
  const latest = sequence[sequence.length - 1];
  return (data.rollout_steps || []).map((step: any) => toForecastStep(step, latest));
}

