#!/usr/bin/env python3
"""
CyberWorld — Operational Threat Scoring Engine
Computes multi-factor risk scores combining attack probability, stage severity,
target asset criticality, and forecast transition velocity.
"""

from typing import Dict, Any

STAGE_SEVERITY_WEIGHTS = {
    'BENIGN': 0.0,
    'RECONNAISSANCE': 0.35,
    'INITIAL_ACCESS': 0.65,
    'LATERAL_MOVEMENT': 0.85,
    'COMMAND_AND_CONTROL': 0.90,
    'EXFILTRATION': 1.00,
}

class ThreatScorer:
    """Multi-factor SOC threat scoring engine."""
    def __init__(
        self,
        w_prob: float = 0.40,
        w_stage: float = 0.30,
        w_asset: float = 0.15,
        w_velocity: float = 0.15,
    ):
        self.w_prob = w_prob
        self.w_stage = w_stage
        self.w_asset = w_asset
        self.w_velocity = w_velocity

    def compute_risk(
        self,
        attack_probability: float,
        current_stage: str,
        predicted_next_stage: str,
        asset_criticality: float = 0.80, # e.g. Domain Controller = 1.0, Workstation = 0.5
    ) -> Dict[str, Any]:
        stage_sev = STAGE_SEVERITY_WEIGHTS.get(current_stage, 0.1)
        next_sev = STAGE_SEVERITY_WEIGHTS.get(predicted_next_stage, stage_sev)

        # Velocity is positive if stage severity escalates
        velocity = max(0.0, next_sev - stage_sev)

        composite_risk = (
            (self.w_prob * attack_probability) +
            (self.w_stage * stage_sev) +
            (self.w_asset * asset_criticality) +
            (self.w_velocity * velocity)
        )
        composite_risk = round(min(1.0, max(0.0, composite_risk)), 3)

        if composite_risk < 0.35:
            level = 'NORMAL'
        elif composite_risk < 0.65:
            level = 'ELEVATED'
        elif composite_risk < 0.80:
            level = 'HIGH'
        else:
            level = 'CRITICAL'

        return {
            'composite_risk_score': composite_risk,
            'threat_level': level,
            'attack_probability': attack_probability,
            'stage_severity': stage_sev,
            'asset_criticality': asset_criticality,
            'forecast_velocity': velocity,
        }
