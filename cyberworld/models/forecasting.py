#!/usr/bin/env python3
"""
CyberWorld — Forecasting & Lead-Time Anticipation Engine
Manages forward trajectories, confidence bounds, and early warning estimation.
"""

from typing import List, Dict, Any

def compute_early_warning_lead_time(
    current_horizon_step: int,
    step_duration_seconds: int = 10,
    detection_latency_ms: float = 24.5
) -> float:
    """
    Computes proactive defender anticipation advantage in seconds:
    Lead Time = (Steps until full compromise) * (Window duration) - (Detection latency)
    """
    lead_time = (current_horizon_step * step_duration_seconds) - (detection_latency_ms / 1000.0)
    return max(0.0, round(lead_time, 1))

class ForecastingEngine:
    """
    Evaluates multi-step predictions and computes early warning metrics.
    """
    def __init__(self, world_model):
        self.world_model = world_model

    def generate_forecast(self, sequence_buffer: List[Dict[str, float]], horizon_steps: int = 5) -> Dict[str, Any]:
        rollout = self.world_model.autoregressive_rollout(sequence_buffer, horizon_steps=horizon_steps)

        # Look for future attack escalation
        escalation_step = None
        for r in rollout:
            if r['attack_probability'] >= 0.70:
                escalation_step = r['step']
                break

        lead_time = compute_early_warning_lead_time(escalation_step if escalation_step else 3)

        return {
            'rollout_steps': rollout,
            'max_projected_risk': max(r['attack_probability'] for r in rollout),
            'early_warning_lead_time_seconds': lead_time,
            'projected_terminal_stage': rollout[-1]['predicted_stage'],
        }
