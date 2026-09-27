#!/usr/bin/env python3
"""CyberWorld — Real Explainability Engine
Computes genuine feature attributions using permutation importance and
optional gradient-based methods (Captum) for the LSTM world model."""

import math
import numpy as np
from typing import Dict, Any, List, Optional
import copy

try:
    from cyberworld.data.feature_engineering.pipeline import FEATURE_NAMES
except ImportError:
    FEATURE_NAMES = []
    
try:
    from cyberworld.models.world_model import STAGE_LABELS
except ImportError:
    STAGE_LABELS = {0: "Normal", 1: "Recon", 2: "Attack", 3: "Exfil"}

try:
    import torch
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

try:
    from captum.attr import IntegratedGradients, FeatureAblation
    CAPTUM_AVAILABLE = True
except ImportError:
    CAPTUM_AVAILABLE = False

FEATURE_DISPLAY_MAPPINGS = {
    'flow_count': ('Flow Concurrency Count', 'VOLUME'),
    'packet_count': ('Total Packet Count', 'VOLUME'),
    'byte_count': ('Total Byte Volume', 'VOLUME'),
    'mean_packet_size': ('Mean Packet Size', 'PACKET'),
    'std_packet_size': ('Packet Size Std Dev', 'PACKET'),
    'min_packet_size': ('Min Packet Size', 'PACKET'),
    'max_packet_size': ('Max Packet Size', 'PACKET'),
    'mean_iat_ms': ('Mean Inter-Arrival Time', 'TIMING'),
    'std_iat_ms': ('IAT Standard Deviation', 'TIMING'),
    'min_iat_ms': ('Min Inter-Arrival Time', 'TIMING'),
    'max_iat_ms': ('Max Inter-Arrival Time', 'TIMING'),
    'syn_count': ('SYN Flag Count', 'FLAGS'),
    'ack_count': ('ACK Flag Count', 'FLAGS'),
    'rst_count': ('RST Flag Count', 'FLAGS'),
    'fin_count': ('FIN Flag Count', 'FLAGS'),
    'psh_count': ('PSH Flag Count', 'FLAGS'),
    'syn_ack_ratio': ('SYN/ACK Imbalance Ratio', 'FLAGS'),
    'rst_ratio': ('TCP RST Reset Ratio', 'FLAGS'),
    'unique_src_ips': ('Unique Source IPs', 'TOPOLOGY'),
    'unique_dst_ips': ('Unique Destination IPs', 'TOPOLOGY'),
    'unique_src_ports': ('Unique Source Ports', 'TOPOLOGY'),
    'unique_dst_ports': ('Unique Destination Ports', 'TOPOLOGY'),
    'src_ip_entropy': ('Source IP Entropy', 'TOPOLOGY'),
    'dst_ip_entropy': ('Destination IP Entropy', 'TOPOLOGY'),
    'dst_port_entropy': ('Destination Port Entropy', 'TOPOLOGY'),
    'tcp_ratio': ('TCP Protocol Ratio', 'VOLUME'),
    'udp_ratio': ('UDP Protocol Ratio', 'VOLUME'),
    'icmp_ratio': ('ICMP Protocol Ratio', 'VOLUME'),
    'bytes_per_second': ('Bytes Per Second', 'VOLUME'),
    'packets_per_second': ('Packets Per Second', 'VOLUME'),
    'bytes_per_flow': ('Bytes Per Flow', 'VOLUME'),
    'packets_per_flow': ('Packets Per Flow', 'VOLUME'),
    'temporal_burstiness': ('Temporal Burstiness Index', 'TIMING'),
}

class ExplainabilityEngine:
    def __init__(self, model: Optional[Any] = None):
        self.model = model

    def _get_baseline_prediction(self, model, sequence: 'torch.Tensor') -> float:
        model.eval()
        with torch.no_grad():
            output = model(sequence)
            if isinstance(output, tuple):
                output = output[0]
            if isinstance(output, dict):
                return float(output.get('risk_score', output.get('stage_probs', torch.zeros(1, 4)).max()).item())
            
            if output.dim() == 2 and output.shape[1] > 1:
                probs = torch.softmax(output, dim=1)
                return float((probs[0, 1:]).sum().item())
            return float(output.mean().item())

    def compute_local_attributions(self, state_vector: Dict[str, Any], model: Optional[Any] = None, sequence: Optional[Any] = None) -> List[Dict[str, Any]]:
        target_model = model if model is not None else self.model
        attributions = []
        
        if target_model is not None and TORCH_AVAILABLE and sequence is not None:
            if not isinstance(sequence, torch.Tensor):
                try:
                    seq_tensor = torch.tensor(sequence, dtype=torch.float32)
                    if seq_tensor.dim() == 2:
                        seq_tensor = seq_tensor.unsqueeze(0)
                except Exception:
                    seq_tensor = None
            else:
                seq_tensor = sequence
                if seq_tensor.dim() == 2:
                    seq_tensor = seq_tensor.unsqueeze(0)
            
            if seq_tensor is not None:
                base_score = self._get_baseline_prediction(target_model, seq_tensor)
                feature_keys = list(state_vector.keys())
                
                contributions = {}
                seq_len = seq_tensor.shape[1]
                
                for idx, f_key in enumerate(feature_keys):
                    if idx >= seq_tensor.shape[2]:
                        break 
                        
                    permuted_seq = seq_tensor.clone()
                    if seq_len > 1:
                        perm_idx = torch.randperm(seq_len)
                        permuted_seq[0, :, idx] = permuted_seq[0, perm_idx, idx]
                    else:
                        permuted_seq[0, :, idx] = 0.0
                        
                    new_score = self._get_baseline_prediction(target_model, permuted_seq)
                    diff = base_score - new_score
                    contributions[f_key] = diff
                
                total_abs_contrib = sum(abs(v) for v in contributions.values())
                if total_abs_contrib == 0:
                    total_abs_contrib = 1.0
                    
                for f_key, diff in contributions.items():
                    val = state_vector.get(f_key, 0.0)
                    display, cat = FEATURE_DISPLAY_MAPPINGS.get(f_key, (f_key.replace('_', ' ').title(), 'UNKNOWN'))
                    norm_contrib = abs(diff) / total_abs_contrib
                    direction = "INCREASES_RISK" if diff > 0 else "DECREASES_RISK"
                    
                    if norm_contrib > 0.01:
                        attributions.append({
                            "feature_key": f_key,
                            "display_name": display,
                            "category": cat,
                            "value": val,
                            "contribution": norm_contrib,
                            "direction": direction,
                            "method": "permutation"
                        })
                
                attributions.sort(key=lambda x: x['contribution'], reverse=True)
                return attributions[:10]

        for key, val in state_vector.items():
            display, cat = FEATURE_DISPLAY_MAPPINGS.get(key, (key.replace('_', ' ').title(), 'UNKNOWN'))
            contrib = 0.0
            direction = "INCREASES_RISK"
            
            if 'syn' in key.lower() or 'ack' in key.lower() or 'rst' in key.lower():
                contrib = min(val * 0.1, 0.5)
            elif 'entropy' in key.lower():
                contrib = max(0.0, (val - 2.0) * 0.15)
            elif 'count' in key.lower() or 'volume' in key.lower():
                contrib = min(val * 0.001, 0.3)
                
            if contrib > 0.05:
                attributions.append({
                    "feature_key": key,
                    "display_name": display,
                    "category": cat,
                    "value": val,
                    "contribution": contrib,
                    "direction": direction,
                    "method": "heuristic"
                })
                
        total_abs_contrib = sum(abs(a['contribution']) for a in attributions)
        if total_abs_contrib > 0:
            for a in attributions:
                a['contribution'] = a['contribution'] / total_abs_contrib
                
        attributions.sort(key=lambda x: x['contribution'], reverse=True)
        return attributions[:10]

    def compute_temporal_attention(self, model: Optional[Any] = None, sequence: Optional[Any] = None, buffer_length: int = 10) -> List[Dict[str, Any]]:
        target_model = model if model is not None else self.model
        attention_weights = []
        
        if target_model is not None and TORCH_AVAILABLE and sequence is not None:
            if not isinstance(sequence, torch.Tensor):
                try:
                    seq_tensor = torch.tensor(sequence, dtype=torch.float32)
                    if seq_tensor.dim() == 2:
                        seq_tensor = seq_tensor.unsqueeze(0)
                except Exception:
                    seq_tensor = None
            else:
                seq_tensor = sequence
                if seq_tensor.dim() == 2:
                    seq_tensor = seq_tensor.unsqueeze(0)
                    
            if seq_tensor is not None:
                seq_tensor.requires_grad_(True)
                target_model.eval()
                try:
                    output = target_model(seq_tensor)
                    if isinstance(output, tuple):
                        output = output[0]
                    if isinstance(output, dict):
                        score = output.get('risk_score', output.get('stage_probs', torch.zeros(1, 4)).sum())
                    else:
                        score = output.sum()
                        
                    score.backward()
                    
                    if seq_tensor.grad is not None:
                        grad_mags = seq_tensor.grad.abs().sum(dim=2).squeeze(0)
                        grad_mags = grad_mags.detach().numpy()
                        
                        total_grad = grad_mags.sum()
                        if total_grad > 0:
                            grad_mags = grad_mags / total_grad
                            
                        seq_len = len(grad_mags)
                        for i in range(seq_len):
                            attention_weights.append({
                                'time_index': - (seq_len - 1 - i),
                                'weight': float(grad_mags[i]),
                                'method': 'gradient_norm'
                            })
                        return attention_weights[-buffer_length:]
                except Exception:
                    pass

        weights = [math.exp(-0.5 * i) for i in range(buffer_length)]
        total = sum(weights)
        
        for i in range(buffer_length):
            attention_weights.append({
                'time_index': -i,
                'weight': weights[i] / total,
                'method': 'estimated'
            })
            
        return attention_weights[::-1]
