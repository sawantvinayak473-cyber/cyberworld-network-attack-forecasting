#!/usr/bin/env python3
"""
CyberWorld — Network Feature Engineering Pipeline
Transforms discrete packet flows into fixed-dimension temporal state vectors S(t).
Supports 10s, 30s, 60s, 120s windowing, empty window safety, and entropy computations.
"""

import math
import datetime
from collections import Counter
from typing import List, Dict, Any, Optional

FEATURE_NAMES = [
    'flow_count', 'packet_count', 'byte_count',
    'mean_packet_size', 'std_packet_size', 'min_packet_size', 'max_packet_size',
    'mean_iat_ms', 'std_iat_ms', 'min_iat_ms', 'max_iat_ms',
    'syn_count', 'ack_count', 'rst_count', 'fin_count', 'psh_count',
    'syn_ack_ratio', 'rst_ratio',
    'unique_src_ips', 'unique_dst_ips', 'unique_src_ports', 'unique_dst_ports',
    'src_ip_entropy', 'dst_ip_entropy', 'dst_port_entropy',
    'tcp_ratio', 'udp_ratio', 'icmp_ratio',
    'bytes_per_second', 'packets_per_second', 'bytes_per_flow', 'packets_per_flow',
    'temporal_burstiness'
]

def shannon_entropy(items: List[Any]) -> float:
    """Computes Shannon entropy in base 2 for discrete distribution."""
    if not items:
        return 0.0
    total = len(items)
    counts = Counter(items)
    ent = 0.0
    for cnt in counts.values():
        p = cnt / total
        if p > 0:
            ent -= p * math.log2(p)
    return round(ent, 4)

def parse_iso_or_custom_timestamp(ts_str: str) -> datetime.datetime:
    """Robust timestamp parser for network logs."""
    ts_str = ts_str.strip().replace('T', ' ')
    formats = [
        '%Y-%m-%d %H:%M:%S.%f',
        '%Y-%m-%d %H:%M:%S',
        '%m/%d/%Y %H:%M:%S',
        '%d/%m/%Y %H:%M:%S',
    ]
    for fmt in formats:
        try:
            return datetime.datetime.strptime(ts_str, fmt)
        except ValueError:
            pass
    # Fallback to current time if parsing fails
    return datetime.datetime.utcnow()

class NetworkFeaturePipeline:
    """
    State vector extraction pipeline aggregating raw flows into discrete time windows S(t).
    """

    def __init__(self, window_seconds: int = 10, step_seconds: Optional[int] = None):
        self.window_seconds = window_seconds
        self.step_seconds = step_seconds if step_seconds is not None else window_seconds
        self.feature_names = FEATURE_NAMES

    def extract_window_features(self, flows: List[Dict[str, Any]], window_start: datetime.datetime) -> Dict[str, Any]:
        """
        Extracts fixed-dimension feature vector from flows occurring in [window_start, window_start + window_seconds).
        Guarantees safe output for empty windows.
        """
        duration = float(self.window_seconds)

        if not flows:
            # Baseline zero-state vector for quiescent periods
            feat = {k: 0.0 for k in self.feature_names}
            feat['window_start'] = window_start.strftime('%Y-%m-%d %H:%M:%S')
            feat['ground_truth_stage'] = 'BENIGN'
            feat['is_attack'] = 0
            return feat

        flow_count = len(flows)
        packet_counts = [int(f.get('Total_Packets', 1)) for f in flows]
        byte_counts = [int(f.get('Total_Bytes', 40)) for f in flows]
        iats = [float(f.get('Mean_IAT_ms', 10.0)) for f in flows]

        total_packets = sum(packet_counts)
        total_bytes = sum(byte_counts)

        # Packet size statistics
        packet_sizes = [b / max(1, p) for b, p in zip(byte_counts, packet_counts)]
        mean_pkt = sum(packet_sizes) / flow_count
        variance_pkt = sum((x - mean_pkt) ** 2 for x in packet_sizes) / max(1, flow_count)
        std_pkt = math.sqrt(variance_pkt)
        min_pkt = min(packet_sizes)
        max_pkt = max(packet_sizes)

        # IAT statistics
        mean_iat = sum(iats) / flow_count
        var_iat = sum((x - mean_iat) ** 2 for x in iats) / max(1, flow_count)
        std_iat = math.sqrt(var_iat)
        min_iat = min(iats)
        max_iat = max(iats)

        # Flag counts
        syn = sum(int(f.get('SYN_Flag', 0)) for f in flows)
        ack = sum(int(f.get('ACK_Flag', 0)) for f in flows)
        rst = sum(int(f.get('RST_Flag', 0)) for f in flows)
        fin = sum(int(f.get('FIN_Flag', 0)) for f in flows)
        psh = sum(int(f.get('PSH_Flag', 0)) for f in flows)

        syn_ack_ratio = round(syn / max(1, ack), 3)
        rst_ratio = round(rst / max(1, flow_count), 3)

        # Endpoint diversities
        src_ips = [str(f.get('Src_IP', '')) for f in flows]
        dst_ips = [str(f.get('Dst_IP', '')) for f in flows]
        src_ports = [int(f.get('Src_Port', 0)) for f in flows]
        dst_ports = [int(f.get('Dst_Port', 0)) for f in flows]

        unique_src_ips = len(set(src_ips))
        unique_dst_ips = len(set(dst_ips))
        unique_src_ports = len(set(src_ports))
        unique_dst_ports = len(set(dst_ports))

        src_ip_ent = shannon_entropy(src_ips)
        dst_ip_ent = shannon_entropy(dst_ips)
        dst_port_ent = shannon_entropy(dst_ports)

        # Protocol counts
        protocols = [str(f.get('Protocol', 'TCP')).upper() for f in flows]
        tcp_count = sum(1 for p in protocols if p == 'TCP')
        udp_count = sum(1 for p in protocols if p == 'UDP')
        icmp_count = sum(1 for p in protocols if p == 'ICMP')

        tcp_ratio = round(tcp_count / flow_count, 3)
        udp_ratio = round(udp_count / flow_count, 3)
        icmp_ratio = round(icmp_count / flow_count, 3)

        # Rates
        bytes_per_sec = round(total_bytes / duration, 2)
        packets_per_sec = round(total_packets / duration, 2)
        bytes_per_flow = round(total_bytes / flow_count, 2)
        packets_per_flow = round(total_packets / flow_count, 2)

        # Temporal burstiness = std(IAT) / (mean(IAT) + eps)
        temporal_burstiness = round(std_iat / max(1.0, mean_iat), 3)

        # Ground truth resolution: majority vote or prioritized attack stage
        stages_in_window = [f.get('Label', 'BENIGN') for f in flows]
        attacks_in_window = [s for s in stages_in_window if s != 'BENIGN']
        if attacks_in_window:
            dominant_stage = Counter(attacks_in_window).most_common(1)[0][0]
            is_attack = 1
        else:
            dominant_stage = 'BENIGN'
            is_attack = 0

        vector = {
            'window_start': window_start.strftime('%Y-%m-%d %H:%M:%S'),
            'flow_count': flow_count,
            'packet_count': total_packets,
            'byte_count': total_bytes,
            'mean_packet_size': round(mean_pkt, 2),
            'std_packet_size': round(std_pkt, 2),
            'min_packet_size': round(min_pkt, 2),
            'max_packet_size': round(max_pkt, 2),
            'mean_iat_ms': round(mean_iat, 2),
            'std_iat_ms': round(std_iat, 2),
            'min_iat_ms': round(min_iat, 2),
            'max_iat_ms': round(max_iat, 2),
            'syn_count': syn,
            'ack_count': ack,
            'rst_count': rst,
            'fin_count': fin,
            'psh_count': psh,
            'syn_ack_ratio': syn_ack_ratio,
            'rst_ratio': rst_ratio,
            'unique_src_ips': unique_src_ips,
            'unique_dst_ips': unique_dst_ips,
            'unique_src_ports': unique_src_ports,
            'unique_dst_ports': unique_dst_ports,
            'src_ip_entropy': src_ip_ent,
            'dst_ip_entropy': dst_ip_ent,
            'dst_port_entropy': dst_port_ent,
            'tcp_ratio': tcp_ratio,
            'udp_ratio': udp_ratio,
            'icmp_ratio': icmp_ratio,
            'bytes_per_second': bytes_per_sec,
            'packets_per_second': packets_per_sec,
            'bytes_per_flow': bytes_per_flow,
            'packets_per_flow': packets_per_flow,
            'temporal_burstiness': temporal_burstiness,
            'ground_truth_stage': dominant_stage,
            'is_attack': is_attack,
        }
        return vector

    def process_flow_sequence(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Groups flows into sliding chronological windows without shuffling.
        """
        if not flows:
            return []

        # Parse timestamps
        parsed_flows = []
        for f in flows:
            ts = parse_iso_or_custom_timestamp(str(f.get('Timestamp', '')))
            parsed_flows.append((ts, f))

        parsed_flows.sort(key=lambda x: x[0])

        start_time = parsed_flows[0][0]
        end_time = parsed_flows[-1][0]
        window_delta = datetime.timedelta(seconds=self.window_seconds)
        step_delta = datetime.timedelta(seconds=self.step_seconds)

        current_window_start = start_time
        state_vectors = []

        while current_window_start <= end_time:
            current_window_end = current_window_start + window_delta
            window_flows = [
                f for ts, f in parsed_flows
                if current_window_start <= ts < current_window_end
            ]
            vec = self.extract_window_features(window_flows, current_window_start)
            state_vectors.append(vec)
            current_window_start += step_delta

        return state_vectors
