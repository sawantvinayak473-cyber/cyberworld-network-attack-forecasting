#!/usr/bin/env python3
"""CyberWorld — Forecasting Engine
Autoregressive rollout engine to predict future network states and attack progression."""

import numpy as np
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False


def compute_early_warning_lead_time(
    current_horizon_step: int,
    step_duration_seconds: int = 10,
    detection_latency_ms: float = 24.5,
) -> float:
    """
    Computes proactive defender anticipation advantage in seconds:
    Lead Time = (Steps until full compromise) × (Window duration) - (Detection latency)
    """
    lead_time = (current_horizon_step * step_duration_seconds) - (detection_latency_ms / 1000.0)
    return max(0.0, round(lead_time, 1))

class ForecastingEngine:
    def __init__(self, model: Optional[Any] = None, horizon: int = 5):
        self.model = model
        self.horizon = horizon
        self.is_pytorch = TORCH_AVAILABLE and model is not None
        
    def forecast(self, current_sequence: Any) -> Dict[str, Any]:
        """Generate a forecast for the next `horizon` steps."""
        if self.is_pytorch:
            return self._pytorch_forecast(current_sequence)
        else:
            return self._heuristic_forecast(current_sequence)
            
    def _pytorch_forecast(self, current_sequence: Any) -> Dict[str, Any]:
        """Real autoregressive rollout using the PyTorch world model."""
        self.model.eval()
        
        if not isinstance(current_sequence, torch.Tensor):
            seq = torch.tensor(current_sequence, dtype=torch.float32)
        else:
            seq = current_sequence.clone()
            
        if seq.dim() == 2:
            seq = seq.unsqueeze(0) 
            
        forecasts = []
        confidences = []
        projected_states = []
        
        with torch.no_grad():
            current_input = seq
            
            for step in range(self.horizon):
                output = self.model(current_input)
                
                if isinstance(output, tuple):
                    stage_probs = output[0]
                    next_state = output[1] if len(output) > 1 else current_input[:, -1:, :]
                elif isinstance(output, dict):
                    stage_probs = output.get('stage_probs', torch.zeros(1, 4))
                    next_state = output.get('next_state', current_input[:, -1:, :])
                else:
                    stage_probs = torch.softmax(output, dim=-1)
                    next_state = current_input[:, -1:, :]
                
                probs = torch.softmax(stage_probs, dim=-1)
                max_prob, predicted_stage = torch.max(probs, dim=-1)
                
                confidence_score = float(max_prob.item())
                
                forecasts.append(int(predicted_stage.item()))
                confidences.append(confidence_score)
                projected_states.append(next_state.squeeze(0).numpy())
                
                if next_state.dim() == 2:
                    next_state = next_state.unsqueeze(1)
                current_input = torch.cat([current_input[:, 1:, :], next_state], dim=1)
                
        lead_time = -1
        for i, stage in enumerate(forecasts):
            if stage >= 2:
                lead_time = i + 1
                break
                
        return {
            'forecast_method': 'pytorch_model',
            'horizon': self.horizon,
            'forecast_stages': forecasts,
            'confidences': confidences,
            'early_warning_lead_time': lead_time if lead_time > 0 else None,
            'projected_risk_trend': [f / 3.0 for f in forecasts]
        }
        
    def _heuristic_forecast(self, current_sequence: Any) -> Dict[str, Any]:
        """Fallback heuristic forecast when no model is available."""
        if isinstance(current_sequence, list) or isinstance(current_sequence, np.ndarray):
            val = float(np.mean(current_sequence[-1] if len(current_sequence) > 0 else 0))
        else:
            val = 0.0
            
        base_stage = 0
        if val > 100: base_stage = 1
        if val > 500: base_stage = 2
        if val > 1000: base_stage = 3
        
        forecasts = []
        confidences = []
        
        current_stage = base_stage
        for i in range(self.horizon):
            if np.random.random() < 0.2 and current_stage < 3:
                current_stage += 1
            forecasts.append(current_stage)
            confidences.append(max(0.3, 0.9 - (i * 0.1)))
            
        lead_time = -1
        for i, stage in enumerate(forecasts):
            if stage >= 2:
                lead_time = i + 1
                break
                
        return {
            'forecast_method': 'heuristic_fallback',
            'horizon': self.horizon,
            'forecast_stages': forecasts,
            'confidences': confidences,
            'early_warning_lead_time': lead_time if lead_time > 0 else None,
            'projected_risk_trend': [f / 3.0 for f in forecasts]
        }
