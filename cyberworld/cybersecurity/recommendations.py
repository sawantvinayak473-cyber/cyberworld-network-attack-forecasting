#!/usr/bin/env python3
"""
CyberWorld — Proactive Defensive Recommendations Engine
Synthesizes recommended containment playbooks based on predicted forward attack stages.
"""

from typing import List, Dict, Any

STAGE_RECOMMENDATIONS = {
    'RECONNAISSANCE': [
        {'action': 'Block Scanning Source IP', 'command': 'iptables -A INPUT -s {src_ip} -j DROP', 'urgency': 'MEDIUM'},
        {'action': 'Rate-limit Ingress TCP SYN Probes', 'command': 'iptables -A INPUT -p tcp --syn -m limit --limit 5/s -j ACCEPT', 'urgency': 'MEDIUM'},
        {'action': 'Deploy L4 Decoy / Honeypot Listener', 'command': 'systemctl start honeyd.service', 'urgency': 'LOW'},
    ],
    'INITIAL_ACCESS': [
        {'action': 'Enforce Perimeter MFA Verification', 'command': 'pam_tally2 --user admin --reset', 'urgency': 'HIGH'},
        {'action': 'Quarantine Ingress HTTP/SSH Session', 'command': 'conntrack -D -s {src_ip}', 'urgency': 'HIGH'},
        {'action': 'Trigger Container Memory Snapshot', 'command': 'docker commit $(docker ps -q) incident_snapshot', 'urgency': 'HIGH'},
    ],
    'LATERAL_MOVEMENT': [
        {'action': 'Isolate Host VLAN Segment', 'command': 'switch-cli set port 24 vlan 999', 'urgency': 'CRITICAL'},
        {'action': 'Revoke Active Kerberos TGT Tokens', 'command': 'klist purge', 'urgency': 'CRITICAL'},
        {'action': 'Block East-West SMB/RPC Communication', 'command': 'iptables -A FORWARD -p tcp --dport 445 -j REJECT', 'urgency': 'CRITICAL'},
    ],
    'COMMAND_AND_CONTROL': [
        {'action': 'Sinkhole External C2 Domain / IP', 'command': 'unbound-control local_zone {dst_ip} refuse', 'urgency': 'CRITICAL'},
        {'action': 'Sever Persistent Outbound Connection', 'command': 'tcpkill -i eth0 host {dst_ip}', 'urgency': 'CRITICAL'},
        {'action': 'Revoke Compromised Service Account Keys', 'command': 'vault token revoke -mode=path auth/approle', 'urgency': 'CRITICAL'},
    ],
    'EXFILTRATION': [
        {'action': 'Emergency Egress Bandwidth Throttling', 'command': 'tc qdisc add dev eth0 root tbf rate 10kbit burst 32kbit latency 400ms', 'urgency': 'EMERGENCY'},
        {'action': 'Sever Outbound Data Pipeline', 'command': 'iptables -I OUTPUT -d {dst_ip} -j DROP', 'urgency': 'EMERGENCY'},
        {'action': 'Initiate Forensic Chain-of-Custody Capture', 'command': 'dumpcap -i eth0 -w /forensics/exfil_capture.pcap', 'urgency': 'EMERGENCY'},
    ],
}

class RecommendationEngine:
    def get_recommendations(self, current_stage: str, predicted_next_stage: str, src_ip: str, dst_ip: str) -> List[Dict[str, Any]]:
        # Prioritize forward projected stage for proactive defence
        target_stage = predicted_next_stage if predicted_next_stage != 'BENIGN' else current_stage
        recs = STAGE_RECOMMENDATIONS.get(target_stage, STAGE_RECOMMENDATIONS.get('RECONNAISSANCE', []))

        formatted = []
        for r in recs:
            cmd = r['command'].replace('{src_ip}', src_ip).replace('{dst_ip}', dst_ip)
            formatted.append({
                'action': r['action'],
                'executable_command': cmd,
                'urgency': r['urgency'],
                'target_stage': target_stage,
            })
        return formatted
