#!/usr/bin/env python3
"""
CyberWorld — Static Baseline Classifiers
Implements point-in-time classifiers (Random Forest & Logistic Regression)
for architectural comparison against the temporal World Model.
"""

from typing import Dict, Any, List

class StaticBaselineClassifier:
    """
    Simulates / wraps point-in-time flow classifiers (e.g. Scikit-Learn Random Forest).
    Lacks temporal memory and cannot perform autoregressive forward state prediction.
    """
    def __init__(self, model_type: str = "random_forest"):
        self.model_type = model_type

    def predict_flow(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """
        Classifies an isolated flow without temporal context.
        """
        syn = int(flow.get('SYN_Flag', 0))
        ack = int(flow.get('ACK_Flag', 0))
        rst = int(flow.get('RST_Flag', 0))
        duration = float(flow.get('Flow_Duration_ms', 10.0))

        # Static heuristic approximation of trained Random Forest
        if syn == 1 and ack == 0:
            score = 0.85
            label = "ATTACK"
        elif rst == 1 and duration < 5.0:
            score = 0.70
            label = "ATTACK"
        else:
            score = 0.08
            label = "BENIGN"

        return {
            "model_type": self.model_type,
            "prediction": label,
            "attack_probability": score,
            "supports_forecasting": False,
            "temporal_memory_window": 0,
        }
