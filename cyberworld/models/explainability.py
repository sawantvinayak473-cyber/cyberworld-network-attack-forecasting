#!/usr/bin/env python3
"""
CyberWorld — Explainability Engine (SHAP & Attention)
Calculates local feature attribution and temporal attention allocation across window buffers.
"""

from typing import Dict, Any, List

FEATURE_DISPLAY_MAPPINGS = {
    'syn_ack_ratio': ('SYN/ACK Imbalance Ratio', 'FLAGS'),
    'dst_port_entropy': ('Destination Port Entropy', 'TOPOLOGY'),
    'std_iat_ms': ('Inter-Arrival Time (IAT) Variance', 'TIMING'),
    'temporal_burstiness': ('Temporal Burstiness Index', 'TIMING'),
    'unique_dst_ips': ('Unique Target Host Spread', 'TOPOLOGY'),
    'bytes_per_flow': ('Flow Volume Density (Bytes/Flow)', 'VOLUME'),
    'rst_ratio': ('TCP RST Reset Ratio', 'FLAGS'),
    'flow_count': ('Flow Concurrency Count', 'VOLUME'),
}

class ExplainabilityEngine:
    """
    Computes directional feature attributions (SHAP surrogate) explaining why a given
    network time-window was flagged as high or elevated risk.
    """
    def __init__(self):
        self.mappings = FEATURE_DISPLAY_MAPPINGS

    def compute_local_attributions(self, state_vector: Dict[str, Any]) -> List[Dict[str, Any]]:
        attributions = []

        syn_ack = float(state_vector.get('syn_ack_ratio', 0.1))
        port_ent = float(state_vector.get('dst_port_entropy', 1.0))
        burstiness = float(state_vector.get('temporal_burstiness', 1.0))
        iat_std = float(state_vector.get('std_iat_ms', 50.0))
        bytes_flow = float(state_vector.get('bytes_per_flow', 200.0))

        # SYN/ACK attribution
        syn_contrib = (syn_ack - 0.2) * 0.18
        attributions.append({
            'feature_key': 'syn_ack_ratio',
            'display_name': 'SYN/ACK Imbalance Ratio',
            'category': 'FLAGS',
            'value': syn_ack,
            'contribution': round(syn_contrib, 4),
            'direction': 'INCREASES_RISK' if syn_contrib > 0 else 'DECREASES_RISK'
        })

        # Port Entropy attribution
        port_contrib = (port_ent - 1.8) * 0.12
        attributions.append({
            'feature_key': 'dst_port_entropy',
            'display_name': 'Destination Port Entropy',
            'category': 'TOPOLOGY',
            'value': port_ent,
            'contribution': round(port_contrib, 4),
            'direction': 'INCREASES_RISK' if port_contrib > 0 else 'DECREASES_RISK'
        })

        # Burstiness attribution
        burst_contrib = (burstiness - 1.2) * 0.10
        attributions.append({
            'feature_key': 'temporal_burstiness',
            'display_name': 'Temporal Burstiness Index',
            'category': 'TIMING',
            'value': burstiness,
            'contribution': round(burst_contrib, 4),
            'direction': 'INCREASES_RISK' if burst_contrib > 0 else 'DECREASES_RISK'
        })

        # IAT Variance attribution
        iat_contrib = (iat_std - 80.0) * 0.001
        attributions.append({
            'feature_key': 'std_iat_ms',
            'display_name': 'Inter-Arrival Time (IAT) Variance',
            'category': 'TIMING',
            'value': iat_std,
            'contribution': round(iat_contrib, 4),
            'direction': 'INCREASES_RISK' if iat_contrib > 0 else 'DECREASES_RISK'
        })

        # Bytes per flow attribution
        byte_contrib = (bytes_flow - 300.0) * 0.0003
        attributions.append({
            'feature_key': 'bytes_per_flow',
            'display_name': 'Flow Volume Density (Bytes/Flow)',
            'category': 'VOLUME',
            'value': bytes_flow,
            'contribution': round(byte_contrib, 4),
            'direction': 'INCREASES_RISK' if byte_contrib > 0 else 'DECREASES_RISK'
        })

        # Sort by absolute impact descending
        attributions.sort(key=lambda x: abs(x['contribution']), reverse=True)
        return attributions

    def compute_temporal_attention(self, buffer_length: int = 10) -> List[Dict[str, Any]]:
        """
        Returns attention weights across temporal sequence buffer.
        """
        weights = []
        for i in range(buffer_length):
            offset = buffer_length - 1 - i
            decay = 0.5 * (0.8 ** offset)
            if offset == 0:
                decay += 0.3
            weights.append({
                'time_step': f"S(t-{offset})" if offset > 0 else "S(t)",
                'weight': round(decay, 3)
            })
        return weights
