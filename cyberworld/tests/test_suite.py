#!/usr/bin/env python3
"""
CyberWorld — Comprehensive Test Suite
Validates feature engineering, temporal windowing, World Model forward rollout,
threat scoring, MITRE ATT&CK mapping, alert deduplication, and SQLite persistence.
Uses standard library unittest for zero external dependency execution.
"""

import os
import sys
import unittest
import datetime

# Add root directory to sys.path
root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, root_dir)
sys.path.insert(0, os.path.join(root_dir, 'cyberworld'))

from cyberworld.data.feature_engineering.pipeline import NetworkFeaturePipeline, shannon_entropy, FEATURE_NAMES
from cyberworld.data.generate_sample import generate_chronological_dataset
from cyberworld.models.world_model import WorldModelPredictor
from cyberworld.models.forecasting import compute_early_warning_lead_time, ForecastingEngine
from cyberworld.models.explainability import ExplainabilityEngine
from cyberworld.cybersecurity.mitre import MitreMapper
from cyberworld.cybersecurity.threat_scoring import ThreatScorer
from cyberworld.cybersecurity.alert_engine import AlertEngine
from cyberworld.cybersecurity.recommendations import RecommendationEngine
from cyberworld.storage.database import CyberWorldDatabase

class TestCyberWorld(unittest.TestCase):

    def setUp(self):
        self.pipeline = NetworkFeaturePipeline(window_seconds=10)
        self.world_model = WorldModelPredictor()
        self.forecasting = ForecastingEngine(self.world_model)
        self.explainability = ExplainabilityEngine()
        self.mitre = MitreMapper()
        self.scorer = ThreatScorer()
        self.alert_engine = AlertEngine(suppression_window_seconds=60)
        self.db = CyberWorldDatabase(db_path=":memory:")

    # 1. Empty window feature extraction
    def test_feature_pipeline_empty_window(self):
        now = datetime.datetime(2026, 9, 8, 12, 0, 0)
        feat = self.pipeline.extract_window_features([], now)
        self.assertEqual(feat['flow_count'], 0)
        self.assertEqual(feat['byte_count'], 0)
        self.assertEqual(feat['ground_truth_stage'], 'BENIGN')
        self.assertEqual(feat['is_attack'], 0)

    # 2. Consistent feature vector dimension
    def test_feature_pipeline_vector_dim(self):
        now = datetime.datetime(2026, 9, 8, 12, 0, 0)
        dummy_flow = [{
            'Timestamp': '2026-09-08 12:00:01.000',
            'Src_IP': '192.168.1.5',
            'Dst_IP': '10.0.0.12',
            'Src_Port': 50000,
            'Dst_Port': 80,
            'Protocol': 'TCP',
            'Total_Packets': 10,
            'Total_Bytes': 1000,
            'Mean_IAT_ms': 50.0,
            'SYN_Flag': 1,
            'ACK_Flag': 1,
        }]
        feat = self.pipeline.extract_window_features(dummy_flow, now)
        for fname in FEATURE_NAMES:
            self.assertIn(fname, feat, f"Missing feature: {fname}")

    # 3. Shannon Entropy calculation
    def test_shannon_entropy(self):
        homogeneous = [80, 80, 80, 80]
        self.assertEqual(shannon_entropy(homogeneous), 0.0)
        diverse = [80, 443, 22, 3389]
        self.assertAlmostEqual(shannon_entropy(diverse), 2.0, places=2)

    # 4. Temporal burstiness calculation
    def test_temporal_burstiness(self):
        now = datetime.datetime(2026, 9, 8, 12, 0, 0)
        bursty_flows = [
            {'Total_Packets': 5, 'Total_Bytes': 300, 'Mean_IAT_ms': 1.0},
            {'Total_Packets': 5, 'Total_Bytes': 300, 'Mean_IAT_ms': 300.0},
        ]
        feat = self.pipeline.extract_window_features(bursty_flows, now)
        self.assertGreater(feat['temporal_burstiness'], 0.5)

    # 5. Chronological synthetic telemetry order
    def test_synthetic_data_chronological_order(self):
        dataset = generate_chronological_dataset(
            output_path="artifacts/test_traffic.csv",
            total_scenarios=2,
            records_per_stage=20,
            seed=123
        )
        timestamps = [row['Timestamp'] for row in dataset]
        self.assertEqual(timestamps, sorted(timestamps), "Timestamps must be monotonically strictly non-decreasing")

    # 6. Attack scenarios generation count
    def test_synthetic_data_scenarios(self):
        dataset = generate_chronological_dataset(
            output_path="artifacts/test_traffic.csv",
            total_scenarios=3,
            records_per_stage=15,
            seed=999
        )
        scenarios_seen = set(row['Scenario'] for row in dataset)
        self.assertEqual(len(scenarios_seen), 3)

    # 7. World model single-step forward inference
    def test_world_model_prediction(self):
        dummy_seq = [
            {'syn_ack_ratio': 2.5, 'dst_port_entropy': 4.1, 'std_iat_ms': 80.0, 'flow_count': 90, 'temporal_burstiness': 2.5}
        ]
        pred = self.world_model.predict_step(dummy_seq)
        self.assertIn('attack_probability', pred)
        self.assertIn('predicted_stage', pred)
        self.assertGreater(pred['attack_probability'], 0.5)

    # 8. Autoregressive multi-step forward rollout
    def test_world_model_multistep_rollout(self):
        dummy_seq = [
            {'syn_ack_ratio': 3.0, 'dst_port_entropy': 4.5, 'std_iat_ms': 90.0, 'flow_count': 100, 'temporal_burstiness': 3.0}
        ]
        rollout = self.world_model.autoregressive_rollout(dummy_seq, horizon_steps=5)
        self.assertEqual(len(rollout), 5)
        self.assertEqual(rollout[0]['step'], 1)
        self.assertEqual(rollout[-1]['step'], 5)
        self.assertGreaterEqual(rollout[-1]['horizon_seconds'], 50)

    # 9. Threat scoring weights and categories
    def test_threat_scoring_weights(self):
        high_risk = self.scorer.compute_risk(
            attack_probability=0.98,
            current_stage='EXFILTRATION',
            predicted_next_stage='EXFILTRATION',
            asset_criticality=1.0
        )
        self.assertEqual(high_risk['threat_level'], 'CRITICAL')
        self.assertGreater(high_risk['composite_risk_score'], 0.80)

        low_risk = self.scorer.compute_risk(
            attack_probability=0.05,
            current_stage='BENIGN',
            predicted_next_stage='BENIGN',
            asset_criticality=0.2
        )
        self.assertEqual(low_risk['threat_level'], 'NORMAL')

    # 10. Alert deduplication suppression window
    def test_alert_engine_deduplication(self):
        # First alert triggered
        a1 = self.alert_engine.process_state(
            timestamp_str="2026-09-08 12:00:00",
            source_ip="192.168.1.100",
            destination_ip="10.0.0.5",
            attack_probability=0.88,
            current_stage="RECONNAISSANCE",
            predicted_next_stage="INITIAL_ACCESS",
            lead_time_seconds=120.0,
            features=[],
            mitre_candidates=[]
        )
        self.assertIsNotNone(a1)

        # Immediate repeat should be suppressed by deduplication
        a2 = self.alert_engine.process_state(
            timestamp_str="2026-09-08 12:00:05",
            source_ip="192.168.1.100",
            destination_ip="10.0.0.5",
            attack_probability=0.91,
            current_stage="RECONNAISSANCE",
            predicted_next_stage="INITIAL_ACCESS",
            lead_time_seconds=115.0,
            features=[],
            mitre_candidates=[]
        )
        self.assertIsNone(a2, "Duplicate alert within suppression window must be suppressed")
        self.assertEqual(self.alert_engine.active_alerts[0]['count'], 2)

    # 11. MITRE ATT&CK mapping coverage
    def test_mitre_mapping_coverage(self):
        stages = ['RECONNAISSANCE', 'INITIAL_ACCESS', 'LATERAL_MOVEMENT', 'COMMAND_AND_CONTROL', 'EXFILTRATION']
        for s in stages:
            cands = self.mitre.get_candidates_for_stage(s)
            self.assertGreater(len(cands), 0, f"Stage {s} must have mapped MITRE techniques")
            for c in cands:
                self.assertIn('id', c)
                self.assertIn('name', c)
                self.assertIn('evidence', c)

    # 12. Defensive containment recommendations
    def test_recommendations_generation(self):
        recs_engine = RecommendationEngine()
        recs = recs_engine.get_recommendations(
            current_stage='RECONNAISSANCE',
            predicted_next_stage='INITIAL_ACCESS',
            src_ip='192.168.1.105',
            dst_ip='10.0.0.12'
        )
        self.assertGreater(len(recs), 0)
        has_src_ip = any('192.168.1.105' in r['executable_command'] for r in recs)
        self.assertTrue(has_src_ip, "At least one command should reference the source IP for quarantine")

    # 13. Lead time calculation
    def test_lead_time_calculation(self):
        lead = compute_early_warning_lead_time(current_horizon_step=4, step_duration_seconds=10)
        self.assertAlmostEqual(lead, 40.0, delta=1.0)

    # 14. SQLite database persistence
    def test_sqlite_database_persistence(self):
        alert_item = {
            'id': 'ALT-999999',
            'timestamp': '2026-09-08 14:00:00',
            'severity': 'HIGH',
            'status': 'NEW',
            'source_ip': '192.168.1.50',
            'destination_ip': '10.0.0.2',
            'current_stage': 'INITIAL_ACCESS',
            'predicted_next_stage': 'LATERAL_MOVEMENT',
            'attack_probability': 0.78,
            'early_warning_lead_time_sec': 95.0,
            'count': 1,
            'analyst_notes': 'Initial review',
        }
        self.db.insert_alert(alert_item)
        stored = self.db.get_all_alerts()
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]['alert_id'], 'ALT-999999')

        # Update notes
        self.db.update_alert_notes('ALT-999999', 'Firewall rule applied')
        updated = self.db.get_all_alerts()
        self.assertEqual(updated[0]['analyst_notes'], 'Firewall rule applied')

    # 15. Explainability SHAP local attribution
    def test_explainability_attributions(self):
        state = {'syn_ack_ratio': 3.5, 'dst_port_entropy': 4.0, 'temporal_burstiness': 2.8}
        attrs = self.explainability.compute_local_attributions(state)
        self.assertGreater(len(attrs), 0)
        top_driver = attrs[0]
        self.assertEqual(top_driver['direction'], 'INCREASES_RISK')

if __name__ == '__main__':
    unittest.main()
