#!/usr/bin/env python3
"""
CyberWorld — Synthetic Chronological Network Telemetry Generator
Generates realistic network flow records preserving strict temporal sequence
for multiple attack scenarios without random shuffling.
Supports standard library (csv, random, math, datetime) with zero external dependencies.
"""

import os
import sys
import csv
import math
import random
import datetime
import argparse

STAGES = [
    'BENIGN',
    'RECONNAISSANCE',
    'INITIAL_ACCESS',
    'LATERAL_MOVEMENT',
    'COMMAND_AND_CONTROL',
    'EXFILTRATION',
]

def generate_chronological_dataset(
    output_path: str = "artifacts/sample_traffic.csv",
    base_timestamp: datetime.datetime = None,
    total_scenarios: int = 5,
    records_per_stage: int = 150,
    seed: int = 42,
):
    """
    Generates chronological network telemetry across 5 distinct attack scenarios.
    Ensures strict temporal monotonicity, realistic TCP flag relationships,
    and distinct flow/packet signatures without third-party library dependencies.
    """
    random.seed(seed)
    if base_timestamp is None:
        base_timestamp = datetime.datetime(2026, 9, 8, 8, 0, 0)

    rows = []
    current_time = base_timestamp

    scenarios = [
        # Scenario 1: Full Kill Chain
        ['BENIGN', 'RECONNAISSANCE', 'INITIAL_ACCESS', 'LATERAL_MOVEMENT', 'COMMAND_AND_CONTROL', 'BENIGN'],
        # Scenario 2: Probed Reconnaissance (Aborted / Evaded)
        ['BENIGN', 'RECONNAISSANCE', 'BENIGN', 'BENIGN'],
        # Scenario 3: Fast Credential Spray & Lateral Pivot
        ['BENIGN', 'INITIAL_ACCESS', 'LATERAL_MOVEMENT', 'BENIGN'],
        # Scenario 4: Covert C2 Beaconing
        ['BENIGN', 'COMMAND_AND_CONTROL', 'BENIGN'],
        # Scenario 5: Rapid Staged Exfiltration Burst
        ['BENIGN', 'COMMAND_AND_CONTROL', 'EXFILTRATION', 'BENIGN'],
    ]

    fieldnames = [
        'Flow_ID', 'Timestamp', 'Scenario', 'Src_IP', 'Dst_IP', 'Src_Port', 'Dst_Port',
        'Protocol', 'Flow_Duration_ms', 'Total_Packets', 'Total_Bytes', 'Bytes_Per_Packet',
        'Mean_IAT_ms', 'SYN_Flag', 'ACK_Flag', 'RST_Flag', 'FIN_Flag', 'PSH_Flag',
        'TTL', 'Payload_Entropy', 'Is_Attack', 'Label'
    ]

    label_counts = {s: 0 for s in STAGES}
    flow_id = 1

    for sc_idx, stages_sequence in enumerate(scenarios[:total_scenarios]):
        scenario_name = f"scenario_{sc_idx + 1}"
        for stage in stages_sequence:
            is_attack = (stage != 'BENIGN')
            num_flows = records_per_stage + random.randint(-15, 20)

            for _ in range(num_flows):
                if stage == 'RECONNAISSANCE':
                    iat_ms = random.expovariate(1.0 / 35.0) + 5.0
                    duration_ms = random.uniform(5.0, 45.0)
                    src_ip = "192.168.1.105"
                    dst_ip = f"10.0.0.{random.randint(2, 60)}"
                    src_port = random.randint(49152, 65535)
                    dst_port = random.randint(1, 4000)
                    protocol = "TCP"
                    syn_flag = 1
                    ack_flag = 0 if random.random() < 0.85 else 1
                    rst_flag = 1 if random.random() < 0.4 else 0
                    fin_flag = 0
                    psh_flag = 0
                    total_packets = random.randint(2, 6)
                    total_bytes = total_packets * random.randint(40, 70)
                    ttl = int(random.gauss(54, 3))
                    payload_entropy = random.uniform(1.2, 2.5)

                elif stage == 'INITIAL_ACCESS':
                    iat_ms = random.expovariate(1.0 / 85.0) + 10.0
                    duration_ms = random.uniform(40.0, 250.0)
                    src_ip = "192.168.1.105"
                    dst_ip = "10.0.0.12"
                    src_port = random.randint(49152, 65535)
                    dst_port = random.choice([22, 445, 3389, 80, 443])
                    protocol = "TCP"
                    syn_flag = 1
                    ack_flag = 1
                    rst_flag = 1 if random.random() < 0.25 else 0
                    fin_flag = 1 if random.random() < 0.2 else 0
                    psh_flag = 1
                    total_packets = random.randint(8, 25)
                    total_bytes = total_packets * random.randint(80, 200)
                    ttl = int(random.gauss(64, 1))
                    payload_entropy = random.uniform(2.8, 3.8)

                elif stage == 'LATERAL_MOVEMENT':
                    iat_ms = random.expovariate(1.0 / 120.0) + 20.0
                    duration_ms = random.uniform(100.0, 600.0)
                    src_ip = "10.0.0.12"
                    dst_ip = f"10.0.0.{random.randint(20, 35)}"
                    src_port = random.randint(49152, 65535)
                    dst_port = random.choice([445, 3389, 5985, 135])
                    protocol = "TCP"
                    syn_flag = 1
                    ack_flag = 1
                    rst_flag = 0
                    fin_flag = 1 if random.random() < 0.3 else 0
                    psh_flag = 1
                    total_packets = random.randint(15, 60)
                    total_bytes = total_packets * random.randint(150, 450)
                    ttl = 64
                    payload_entropy = random.uniform(3.2, 4.1)

                elif stage == 'COMMAND_AND_CONTROL':
                    iat_ms = float(random.gauss(300.0, 15.0))
                    duration_ms = random.uniform(80.0, 300.0)
                    src_ip = "10.0.0.12"
                    dst_ip = "198.51.100.44"
                    src_port = random.randint(49152, 65535)
                    dst_port = 443
                    protocol = "TCP"
                    syn_flag = 1
                    ack_flag = 1
                    rst_flag = 0
                    fin_flag = 1 if random.random() < 0.2 else 0
                    psh_flag = 1
                    total_packets = random.randint(6, 16)
                    total_bytes = total_packets * random.randint(90, 180)
                    ttl = 64
                    payload_entropy = random.uniform(4.0, 4.6)

                elif stage == 'EXFILTRATION':
                    iat_ms = random.expovariate(1.0 / 20.0) + 5.0
                    duration_ms = random.uniform(200.0, 1200.0)
                    src_ip = "10.0.0.12"
                    dst_ip = "198.51.100.44"
                    src_port = random.randint(49152, 65535)
                    dst_port = 8443
                    protocol = "TCP"
                    syn_flag = 1
                    ack_flag = 1
                    rst_flag = 0
                    fin_flag = 0
                    psh_flag = 1
                    total_packets = random.randint(40, 120)
                    total_bytes = total_packets * random.randint(800, 1400)
                    ttl = 64
                    payload_entropy = random.uniform(4.8, 5.2)

                else: # BENIGN
                    iat_ms = random.expovariate(1.0 / 220.0) + 40.0
                    duration_ms = random.uniform(40.0, 800.0)
                    src_ip = f"192.168.1.{random.randint(10, 80)}"
                    dst_ip = random.choice(["10.0.0.5", "10.0.0.8", "172.16.0.2", "142.250.190.46"])
                    src_port = random.randint(49152, 65535)
                    dst_port = random.choice([80, 443, 53, 123, 8080])
                    protocol = "TCP" if random.random() < 0.85 else "UDP"
                    syn_flag = 1 if protocol == "TCP" and random.random() < 0.2 else 0
                    ack_flag = 1 if protocol == "TCP" else 0
                    rst_flag = 1 if random.random() < 0.02 else 0
                    fin_flag = 1 if protocol == "TCP" and random.random() < 0.15 else 0
                    psh_flag = 1 if protocol == "TCP" and random.random() < 0.3 else 0
                    total_packets = random.randint(4, 30)
                    total_bytes = total_packets * random.randint(60, 500)
                    ttl = int(random.choice([64, 128]))
                    payload_entropy = random.uniform(2.0, 3.5)

                current_time += datetime.timedelta(milliseconds=max(2.0, iat_ms))
                label_counts[stage] += 1

                rows.append({
                    'Flow_ID': f"FLW-{flow_id:07d}",
                    'Timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                    'Scenario': scenario_name,
                    'Src_IP': src_ip,
                    'Dst_IP': dst_ip,
                    'Src_Port': src_port,
                    'Dst_Port': dst_port,
                    'Protocol': protocol,
                    'Flow_Duration_ms': round(duration_ms, 2),
                    'Total_Packets': total_packets,
                    'Total_Bytes': total_bytes,
                    'Bytes_Per_Packet': round(total_bytes / max(1, total_packets), 2),
                    'Mean_IAT_ms': round(iat_ms, 2),
                    'SYN_Flag': syn_flag,
                    'ACK_Flag': ack_flag,
                    'RST_Flag': rst_flag,
                    'FIN_Flag': fin_flag,
                    'PSH_Flag': psh_flag,
                    'TTL': ttl,
                    'Payload_Entropy': round(payload_entropy, 3),
                    'Is_Attack': int(is_attack),
                    'Label': stage,
                })
                flow_id += 1

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] Successfully generated {len(rows)} chronological telemetry records.")
    print(f"[+] Saved to: {output_path}")
    print("[+] Label distribution:")
    for k, v in label_counts.items():
        print(f"    {k}: {v}")

    return rows

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate chronological network telemetry")
    parser.add_argument("--output", default="artifacts/sample_traffic.csv", help="Output CSV path")
    parser.add_argument("--records-per-stage", type=int, default=120, help="Flow records per stage")
    args = parser.parse_args()
    generate_chronological_dataset(output_path=args.output, records_per_stage=args.records_per_stage)
