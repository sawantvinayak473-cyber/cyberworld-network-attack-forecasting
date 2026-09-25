#!/usr/bin/env python3
"""
CyberWorld — Alert Generation & Deduplication Engine
Manages incident correlation, threshold triggering, suppression windows,
and SOC analyst investigation statuses.
"""

import time
from typing import Dict, Any, List, Optional

class AlertEngine:
    def __init__(self, suppression_window_seconds: int = 60, threshold: float = 0.35):
        self.suppression_window_seconds = suppression_window_seconds
        self.threshold = threshold
        self.active_alerts: List[Dict[str, Any]] = []
        self._dedup_cache: Dict[str, float] = {}

    def process_state(
        self,
        timestamp_str: str,
        source_ip: str,
        destination_ip: str,
        attack_probability: float,
        current_stage: str,
        predicted_next_stage: str,
        lead_time_seconds: float,
        features: List[Dict[str, Any]],
        mitre_candidates: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluates current state against alert thresholds.
        If exceeded and not suppressed, generates a new alert.
        """
        if attack_probability < self.threshold:
            return None

        # Deduplication key
        key = f"{source_ip}->{destination_ip}:{current_stage}"
        current_epoch = time.time()

        if key in self._dedup_cache:
            last_seen = self._dedup_cache[key]
            if (current_epoch - last_seen) < self.suppression_window_seconds:
                # Update existing alert count
                for a in self.active_alerts:
                    if a['dedup_key'] == key:
                        a['count'] += 1
                        a['last_seen'] = timestamp_str
                        return None

        self._dedup_cache[key] = current_epoch
        alert_id = f"ALT-{int(current_epoch * 1000) % 1000000:06d}"

        severity = 'CRITICAL' if attack_probability > 0.85 else 'HIGH' if attack_probability > 0.65 else 'ELEVATED'

        new_alert = {
            'id': alert_id,
            'timestamp': timestamp_str,
            'source_ip': source_ip,
            'destination_ip': destination_ip,
            'severity': severity,
            'status': 'NEW',
            'current_stage': current_stage,
            'predicted_next_stage': predicted_next_stage,
            'attack_probability': attack_probability,
            'early_warning_lead_time_sec': lead_time_seconds,
            'features': features,
            'mitre_candidates': mitre_candidates,
            'count': 1,
            'dedup_key': key,
            'analyst_notes': '',
        }
        self.active_alerts.append(new_alert)
        return new_alert

    def update_alert_status(self, alert_id: str, new_status: str, notes: Optional[str] = None):
        for a in self.active_alerts:
            if a['id'] == alert_id:
                a['status'] = new_status
                if notes is not None:
                    a['analyst_notes'] = notes
                return True
        return False
