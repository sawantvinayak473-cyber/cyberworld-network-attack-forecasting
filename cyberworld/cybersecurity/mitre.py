#!/usr/bin/env python3
"""
CyberWorld — MITRE ATT&CK Mapping Engine
Grounds predictive attack stages into concrete MITRE techniques, tactics,
corroborating evidence signals, and defensive response playbooks.
"""

from typing import List, Dict, Any

MITRE_TECHNIQUE_CATALOG = {
    'RECONNAISSANCE': [
        {
            'id': 'T1046',
            'name': 'Network Service Discovery',
            'tactic': 'Discovery',
            'confidence': 0.94,
            'evidence': [
                'Abnormal destination port entropy > 3.8',
                'Unacknowledged SYN packets to sequential destination ports 1000-2000',
                'Rapid IAT variance indicating automated script scanning',
            ],
            'recommended_action': 'Rate-limit and quarantine source IP on boundary firewall.',
        },
        {
            'id': 'T1595',
            'name': 'Active Scanning: IP Blocks',
            'tactic': 'Reconnaissance',
            'confidence': 0.88,
            'evidence': [
                'High unique destination IP fan-out across internal subnet',
                'ICMP Echo / TCP SYN probe bursts',
            ],
            'recommended_action': 'Deploy blackhole routing for scanning source.',
        },
    ],
    'INITIAL_ACCESS': [
        {
            'id': 'T1110',
            'name': 'Brute Force / Credential Guessing',
            'tactic': 'Credential Access',
            'confidence': 0.91,
            'evidence': [
                'Repeated TCP handshake cycles to port 22/3389 with short session durations',
                'High RST-to-FIN packet ratio',
            ],
            'recommended_action': 'Enforce IP account lockout and multi-factor authentication check.',
        },
        {
            'id': 'T1190',
            'name': 'Exploit Public-Facing Application',
            'tactic': 'Initial Access',
            'confidence': 0.87,
            'evidence': [
                'Abnormal payload entropy on HTTP/HTTPS ingress port 443',
                'Subsequent outbound TCP connection spawned from web server node',
            ],
            'recommended_action': 'Trigger WAF virtual patch and snapshot container memory.',
        },
    ],
    'LATERAL_MOVEMENT': [
        {
            'id': 'T1021.002',
            'name': 'Remote Services: SMB/Windows Admin Shares',
            'tactic': 'Lateral Movement',
            'confidence': 0.95,
            'evidence': [
                'East-West traffic spike across internal ports 445 and 135',
                'Repeated IPC$ and admin$ connection establishment',
            ],
            'recommended_action': 'Isolate source host VLAN; disable NTLM fallback and SMBv1.',
        },
        {
            'id': 'T1021.001',
            'name': 'Remote Desktop Protocol (RDP)',
            'tactic': 'Lateral Movement',
            'confidence': 0.89,
            'evidence': [
                'High volume bidirectional encrypted flows to port 3389',
                'Unusual host-to-host administrative session during non-core hours',
            ],
            'recommended_action': 'Terminate active RDP sessions; revoke Kerberos TGTs for compromised user.',
        },
    ],
    'COMMAND_AND_CONTROL': [
        {
            'id': 'T1071.001',
            'name': 'Application Layer Protocol: Web Protocols (C2 Beacon)',
            'tactic': 'Command and Control',
            'confidence': 0.96,
            'evidence': [
                'Periodic heartbeats with jitter < 5% to external IP 198.51.100.44',
                'Low packet-count sessions with fixed byte payloads',
            ],
            'recommended_action': 'Sinkhole external C2 domain/IP at DNS resolver and border gateway.',
        },
        {
            'id': 'T1573',
            'name': 'Encrypted Channel',
            'tactic': 'Command and Control',
            'confidence': 0.90,
            'evidence': [
                'TLS handshake to untrusted external self-signed certificate authority',
                'Consistent persistent connection duration without user interaction',
            ],
            'recommended_action': 'Reset TLS proxy session; block external IP CIDR.',
        },
    ],
    'EXFILTRATION': [
        {
            'id': 'T1048.003',
            'name': 'Exfiltration Over Alternative Protocol: Encrypted Stream',
            'tactic': 'Exfiltration',
            'confidence': 0.97,
            'evidence': [
                'Massive asymmetry in bytes-sent vs bytes-received (> 20:1)',
                'High sustained egress throughput over non-standard port 8443',
                'High payload Shannon entropy (> 4.8) indicating encrypted data archive',
            ],
            'recommended_action': 'Sever egress connection immediately; throttle outbound bandwidth on firewall.',
        },
    ],
}

class MitreMapper:
    """Grounds stage predictions to MITRE ATT&CK techniques with evidence."""
    def get_candidates_for_stage(self, stage: str) -> List[Dict[str, Any]]:
        return MITRE_TECHNIQUE_CATALOG.get(stage, [])
