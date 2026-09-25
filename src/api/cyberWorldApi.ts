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
