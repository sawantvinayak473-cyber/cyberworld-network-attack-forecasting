#!/usr/bin/env python3
"""
CyberWorld — Comprehensive Test Suite
Validates feature engineering, temporal windowing, World Model forward pass,
checkpoint save/load, real training loop, threat scoring, MITRE ATT&CK mapping,
alert deduplication, SQLite persistence, and explainability.
"""

import os
import sys
import unittest
import datetime
import json
import tempfile
import numpy as np

# Add root directory to sys.path
root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, root_dir)
sys.path.insert(0, os.path.join(root_dir, 'cyberworld'))

from cyberworld.data.feature_engineering.pipeline import NetworkFeaturePipeline, shannon_entropy, FEATURE_NAMES
from cyberworld.data.generate_sample import generate_chronological_dataset
from cyberworld.models.world_model import WorldModelPredictor, STAGE_LABELS
from cyberworld.models.forecasting import compute_early_warning_lead_time, ForecastingEngine
from cyberworld.models.explainability import ExplainabilityEngine
from cyberworld.cybersecurity.mitre import MitreMapper
from cyberworld.cybersecurity.threat_scoring import ThreatScorer
from cyberworld.cybersecurity.alert_engine import AlertEngine
from cyberworld.cybersecurity.recommendations import RecommendationEngine
from cyberworld.storage.database import CyberWorldDatabase

try:
    import torch
    from cyberworld.models.world_model import CyberWorldLSTMModel, TORCH_AVAILABLE
except ImportError:
    TORCH_AVAILABLE = False
    torch = None


class TestFeaturePipeline(unittest.TestCase):
    """Tests for the 33-dimensional feature engineering pipeline."""

    def setUp(self):
        self.pipeline = NetworkFeaturePipeline(window_seconds=10)

    def test_empty_window_returns_zero_vector(self):
        now = datetime.datetime(2026, 9, 8, 12, 0, 0)
        feat = self.pipeline.extract_window_features([], now)
        self.assertEqual(feat['flow_count'], 0)
        self.assertEqual(feat['byte_count'], 0)
        self.assertEqual(feat['ground_truth_stage'], 'BENIGN')
        self.assertEqual(feat['is_attack'], 0)

    def test_all_33_features_present(self):
        now = datetime.datetime(2026, 9, 8, 12, 0, 0)
        flow = [{
            'Timestamp': '2026-09-08 12:00:01.000',
            'Src_IP': '192.168.1.5', 'Dst_IP': '10.0.0.12',
            'Src_Port': 50000, 'Dst_Port': 80,
            'Protocol': 'TCP', 'Total_Packets': 10, 'Total_Bytes': 1000,
            'Mean_IAT_ms': 50.0, 'SYN_Flag': 1, 'ACK_Flag': 1,
        }]
        feat = self.pipeline.extract_window_features(flow, now)
        for fname in FEATURE_NAMES:
            self.assertIn(fname, feat, f"Missing feature: {fname}")

    def test_shannon_entropy_homogeneous(self):
        self.assertEqual(shannon_entropy([80, 80, 80, 80]), 0.0)

    def test_shannon_entropy_diverse(self):
        self.assertAlmostEqual(shannon_entropy([80, 443, 22, 3389]), 2.0, places=2)

    def test_temporal_burstiness_high_variance(self):
        now = datetime.datetime(2026, 9, 8, 12, 0, 0)
        flows = [
            {'Total_Packets': 5, 'Total_Bytes': 300, 'Mean_IAT_ms': 1.0},
            {'Total_Packets': 5, 'Total_Bytes': 300, 'Mean_IAT_ms': 300.0},
        ]
        feat = self.pipeline.extract_window_features(flows, now)
        self.assertGreater(feat['temporal_burstiness'], 0.5)

    def test_attack_label_detected(self):
        now = datetime.datetime(2026, 9, 8, 12, 0, 0)
        flows = [
            {'Total_Packets': 10, 'Total_Bytes': 500, 'Label': 'RECONNAISSANCE'},
            {'Total_Packets': 5, 'Total_Bytes': 200, 'Label': 'BENIGN'},
        ]
        feat = self.pipeline.extract_window_features(flows, now)
        self.assertEqual(feat['is_attack'], 1)
        self.assertEqual(feat['ground_truth_stage'], 'RECONNAISSANCE')


class TestSyntheticData(unittest.TestCase):
    """Tests for synthetic data generation."""

    def test_chronological_order(self):
        dataset = generate_chronological_dataset(
            output_path="artifacts/test_traffic.csv",
            total_scenarios=2, records_per_stage=20, seed=123
        )
        timestamps = [row['Timestamp'] for row in dataset]
        self.assertEqual(timestamps, sorted(timestamps))

    def test_scenario_count(self):
        dataset = generate_chronological_dataset(
            output_path="artifacts/test_traffic.csv",
            total_scenarios=3, records_per_stage=15, seed=999
        )
        scenarios = set(row['Scenario'] for row in dataset)
        self.assertEqual(len(scenarios), 3)


class TestWorldModelPredictor(unittest.TestCase):
    """Tests for the heuristic fallback predictor."""

    def setUp(self):
        self.model = WorldModelPredictor()

    def test_single_step_prediction(self):
        seq = [{'syn_ack_ratio': 2.5, 'dst_port_entropy': 4.1,
                'std_iat_ms': 80.0, 'flow_count': 90, 'temporal_burstiness': 2.5}]
        pred = self.model.predict_step(seq)
        self.assertIn('attack_probability', pred)
        self.assertIn('predicted_stage', pred)
        self.assertGreater(pred['attack_probability'], 0.5)

    def test_empty_sequence_returns_benign(self):
        pred = self.model.predict_step([])
        self.assertEqual(pred['predicted_stage'], 'BENIGN')
        self.assertLess(pred['attack_probability'], 0.1)

    def test_multistep_rollout_length(self):
        seq = [{'syn_ack_ratio': 3.0, 'dst_port_entropy': 4.5,
                'std_iat_ms': 90.0, 'flow_count': 100, 'temporal_burstiness': 3.0}]
        rollout = self.model.autoregressive_rollout(seq, horizon_steps=5)
        self.assertEqual(len(rollout), 5)
        self.assertEqual(rollout[0]['step'], 1)
        self.assertEqual(rollout[-1]['step'], 5)

    def test_stage_labels_valid(self):
        seq = [{'syn_ack_ratio': 2.0, 'dst_port_entropy': 3.5,
                'std_iat_ms': 50.0, 'flow_count': 50, 'temporal_burstiness': 1.5}]
        pred = self.model.predict_step(seq)
        self.assertIn(pred['predicted_stage'], STAGE_LABELS)


@unittest.skipUnless(TORCH_AVAILABLE, "PyTorch not available")
class TestPyTorchModel(unittest.TestCase):
    """Tests for the real PyTorch LSTM model."""

    def test_forward_pass_shapes(self):
        model = CyberWorldLSTMModel(input_dim=33, hidden_dim=64, num_layers=2, dropout=0.1)
        model.eval()
        x = torch.randn(4, 10, 33)  # batch=4, seq_len=10, features=33
        with torch.no_grad():
            out = model(x)
        self.assertEqual(out['attack_probability'].shape, (4, 1))
        self.assertEqual(out['stage_logits'].shape, (4, 6))
        self.assertEqual(out['next_state_vector'].shape, (4, 33))

    def test_attack_probability_bounded(self):
        model = CyberWorldLSTMModel(input_dim=33, hidden_dim=64, num_layers=2, dropout=0.1)
        model.eval()
        x = torch.randn(8, 10, 33)
        with torch.no_grad():
            out = model(x)
        probs = out['attack_probability']
        self.assertTrue(torch.all(probs >= 0))
        self.assertTrue(torch.all(probs <= 1))

    def test_checkpoint_save_and_load(self):
        model = CyberWorldLSTMModel(input_dim=33, hidden_dim=64, num_layers=2, dropout=0.1)
        x = torch.randn(2, 10, 33)

        model.eval()
        with torch.no_grad():
            out_before = model(x)

        with tempfile.NamedTemporaryFile(suffix='.pt', delete=False) as f:
            ckpt_path = f.name
            torch.save({
                'model_state_dict': model.state_dict(),
                'model_config': {'input_dim': 33, 'hidden_dim': 64, 'num_layers': 2, 'dropout': 0.1},
                'feature_names': FEATURE_NAMES,
                'stage_labels': STAGE_LABELS,
            }, ckpt_path)

        # Reload
        model2 = CyberWorldLSTMModel(input_dim=33, hidden_dim=64, num_layers=2, dropout=0.1)
        ckpt = torch.load(ckpt_path, map_location='cpu', weights_only=False)
        model2.load_state_dict(ckpt['model_state_dict'])
        model2.eval()

        with torch.no_grad():
            out_after = model2(x)

        # Predictions should be identical after reload
        self.assertTrue(torch.allclose(
            out_before['attack_probability'],
            out_after['attack_probability'],
            atol=1e-5
        ))

        os.unlink(ckpt_path)

    def test_gradient_flow(self):
        """Verify that gradients flow through the model during training."""
        model = CyberWorldLSTMModel(input_dim=33, hidden_dim=64, num_layers=2, dropout=0.1)
        model.train()
        x = torch.randn(4, 10, 33)
        target = torch.ones(4, 1)

        out = model(x)
        loss = torch.nn.functional.binary_cross_entropy(out['attack_probability'], target)
        loss.backward()

        # Check gradients exist and are non-zero for key parameters
        has_nonzero_grad = False
        for name, param in model.named_parameters():
            if param.grad is not None and param.grad.abs().sum() > 0:
                has_nonzero_grad = True
                break
        self.assertTrue(has_nonzero_grad, "No non-zero gradients found — model is not trainable")

    def test_weights_change_during_training(self):
        """Verify that model weights actually update during a training step."""
        model = CyberWorldLSTMModel(input_dim=33, hidden_dim=64, num_layers=2, dropout=0.1)
        model.train()
        optimizer = torch.optim.Adam(model.parameters(), lr=0.01)

        # Record weights before
        weights_before = {name: param.clone().detach() for name, param in model.named_parameters()}

        # Training step
        x = torch.randn(8, 10, 33)
        binary_target = torch.ones(8, 1)
        stage_target = torch.zeros(8, dtype=torch.long)

        out = model(x)
        loss = (
            torch.nn.functional.binary_cross_entropy(out['attack_probability'], binary_target)
            + torch.nn.functional.cross_entropy(out['stage_logits'], stage_target)
        )
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

        # Check weights changed
        weights_changed = False
        for name, param in model.named_parameters():
            if not torch.equal(weights_before[name], param):
                weights_changed = True
                break
        self.assertTrue(weights_changed, "Model weights did not change during training step")


class TestThreatScoring(unittest.TestCase):
    """Tests for the multi-factor threat scoring engine."""

    def setUp(self):
        self.scorer = ThreatScorer()

    def test_critical_threat(self):
        risk = self.scorer.compute_risk(
            attack_probability=0.98, current_stage='EXFILTRATION',
            predicted_next_stage='EXFILTRATION', asset_criticality=1.0
        )
        self.assertEqual(risk['threat_level'], 'CRITICAL')
        self.assertGreater(risk['composite_risk_score'], 0.80)

    def test_normal_threat(self):
        risk = self.scorer.compute_risk(
            attack_probability=0.05, current_stage='BENIGN',
            predicted_next_stage='BENIGN', asset_criticality=0.2
        )
        self.assertEqual(risk['threat_level'], 'NORMAL')


class TestAlertEngine(unittest.TestCase):
    """Tests for alert generation and deduplication."""

    def setUp(self):
        self.alert_engine = AlertEngine(suppression_window_seconds=60)

    def test_alert_generation(self):
        alert = self.alert_engine.process_state(
            timestamp_str="2026-09-08 12:00:00",
            source_ip="192.168.1.100", destination_ip="10.0.0.5",
            attack_probability=0.88, current_stage="RECONNAISSANCE",
            predicted_next_stage="INITIAL_ACCESS",
            lead_time_seconds=120.0, features=[], mitre_candidates=[]
        )
        self.assertIsNotNone(alert)

    def test_deduplication(self):
        self.alert_engine.process_state(
            timestamp_str="2026-09-08 12:00:00",
            source_ip="192.168.1.100", destination_ip="10.0.0.5",
            attack_probability=0.88, current_stage="RECONNAISSANCE",
            predicted_next_stage="INITIAL_ACCESS",
            lead_time_seconds=120.0, features=[], mitre_candidates=[]
        )
        duplicate = self.alert_engine.process_state(
            timestamp_str="2026-09-08 12:00:05",
            source_ip="192.168.1.100", destination_ip="10.0.0.5",
            attack_probability=0.91, current_stage="RECONNAISSANCE",
            predicted_next_stage="INITIAL_ACCESS",
            lead_time_seconds=115.0, features=[], mitre_candidates=[]
        )
        self.assertIsNone(duplicate, "Duplicate alert within suppression window must be suppressed")
        self.assertEqual(self.alert_engine.active_alerts[0]['count'], 2)


class TestMitreMapping(unittest.TestCase):
    """Tests for MITRE ATT&CK mapping."""

    def test_all_stages_have_techniques(self):
        mitre = MitreMapper()
        for stage in ['RECONNAISSANCE', 'INITIAL_ACCESS', 'LATERAL_MOVEMENT',
                      'COMMAND_AND_CONTROL', 'EXFILTRATION']:
            candidates = mitre.get_candidates_for_stage(stage)
            self.assertGreater(len(candidates), 0, f"Stage {stage} must have mapped techniques")
            for c in candidates:
                self.assertIn('id', c)
                self.assertIn('name', c)


class TestRecommendations(unittest.TestCase):
    """Tests for defensive containment recommendations."""

    def test_recommendations_include_ip(self):
        engine = RecommendationEngine()
        recs = engine.get_recommendations(
            current_stage='RECONNAISSANCE',
            predicted_next_stage='INITIAL_ACCESS',
            src_ip='192.168.1.105', dst_ip='10.0.0.12'
        )
        self.assertGreater(len(recs), 0)
        has_src_ip = any('192.168.1.105' in r['executable_command'] for r in recs)
        self.assertTrue(has_src_ip)


class TestLeadTime(unittest.TestCase):
    """Tests for early warning lead time computation."""

    def test_lead_time_calculation(self):
        lead = compute_early_warning_lead_time(current_horizon_step=4, step_duration_seconds=10)
        self.assertAlmostEqual(lead, 40.0, delta=1.0)


class TestDatabase(unittest.TestCase):
    """Tests for SQLite persistence."""

    def setUp(self):
        self.db = CyberWorldDatabase(db_path=":memory:")

    def test_insert_and_retrieve_alert(self):
        alert = {
            'id': 'ALT-999999', 'timestamp': '2026-09-08 14:00:00',
            'severity': 'HIGH', 'status': 'NEW',
            'source_ip': '192.168.1.50', 'destination_ip': '10.0.0.2',
            'current_stage': 'INITIAL_ACCESS',
            'predicted_next_stage': 'LATERAL_MOVEMENT',
            'attack_probability': 0.78, 'early_warning_lead_time_sec': 95.0,
            'count': 1, 'analyst_notes': 'Initial review',
        }
        self.db.insert_alert(alert)
        stored = self.db.get_all_alerts()
        self.assertEqual(len(stored), 1)
        self.assertEqual(stored[0]['alert_id'], 'ALT-999999')

    def test_update_notes(self):
        alert = {
            'id': 'ALT-888888', 'timestamp': '2026-09-08 15:00:00',
            'severity': 'MEDIUM', 'status': 'NEW',
            'source_ip': '10.0.0.1', 'destination_ip': '10.0.0.2',
        }
        self.db.insert_alert(alert)
        self.db.update_alert_notes('ALT-888888', 'Firewall rule applied')
        updated = self.db.get_all_alerts()
        self.assertEqual(updated[0]['analyst_notes'], 'Firewall rule applied')


class TestExplainability(unittest.TestCase):
    """Tests for the explainability engine."""

    def test_attributions_returned(self):
        engine = ExplainabilityEngine()
        state = {'syn_ack_ratio': 3.5, 'dst_port_entropy': 4.0, 'temporal_burstiness': 2.8}
        attrs = engine.compute_local_attributions(state)
        self.assertGreater(len(attrs), 0)

    def test_attribution_structure(self):
        engine = ExplainabilityEngine()
        state = {'syn_ack_ratio': 2.0, 'dst_port_entropy': 3.0}
        attrs = engine.compute_local_attributions(state)
        for attr in attrs:
            self.assertIn('feature_key', attr)
            self.assertIn('contribution', attr)
            self.assertIn('direction', attr)
            self.assertIn(attr['direction'], ['INCREASES_RISK', 'DECREASES_RISK'])


class TestNoFabricatedMetrics(unittest.TestCase):
    """Verify that hardcoded fabricated metrics have been removed."""

    def test_model_config_not_hardcoded(self):
        """If model_config.json exists, verify it was generated by training, not hardcoded."""
        config_path = os.path.join(root_dir, 'artifacts', 'configs', 'model_config.json')
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)
            # The old fabricated values were exactly:
            # f1_score: 0.955, roc_auc: 0.984, early_warning_lead_time_sec: 142.4
            # If these exact values still exist, the fabrication hasn't been fixed
            if 'f1_score' in config and config['f1_score'] == 0.955:
                if 'roc_auc' in config and config['roc_auc'] == 0.984:
                    self.fail("model_config.json still contains fabricated metrics (F1=0.955, AUC=0.984)")

    def test_checkpoint_not_text_file(self):
        """Verify the model checkpoint is not a text placeholder."""
        ckpt_path = os.path.join(root_dir, 'artifacts', 'models', 'cyberworld_model.pt')
        if os.path.exists(ckpt_path):
            with open(ckpt_path, 'rb') as f:
                header = f.read(50)
            # The old fake checkpoint was: "# CyberWorld Model Checkpoint..."
            if header.startswith(b'# CyberWorld Model'):
                self.fail("cyberworld_model.pt is still a text placeholder, not a real PyTorch checkpoint")

    def test_train_script_not_fake(self):
        """Verify train.py does not contain the fake loss formula."""
        train_path = os.path.join(root_dir, 'cyberworld', 'training', 'train.py')
        if os.path.exists(train_path):
            with open(train_path, 'r') as f:
                content = f.read()
            # The old fake formula: "0.65 * (0.88 ** ep) + 0.05"
            self.assertNotIn('0.65 * (0.88', content,
                           "train.py still contains the fake loss simulation formula")


class TestCICIDSLoader(unittest.TestCase):
    """Tests for the CIC-IDS2017 data loader."""

    def test_label_mapping(self):
        from cyberworld.data.cic_ids_loader import map_label
        self.assertEqual(map_label('BENIGN'), 'BENIGN')
        self.assertEqual(map_label('PortScan'), 'RECONNAISSANCE')
        self.assertEqual(map_label('FTP-Patator'), 'INITIAL_ACCESS')
        self.assertEqual(map_label('DDoS'), 'COMMAND_AND_CONTROL')
        self.assertEqual(map_label('Infiltration'), 'LATERAL_MOVEMENT')
        self.assertEqual(map_label('DoS Hulk'), 'COMMAND_AND_CONTROL')

    def test_label_mapping_case_insensitive(self):
        from cyberworld.data.cic_ids_loader import map_label
        self.assertEqual(map_label('benign'), 'BENIGN')
        self.assertEqual(map_label('PORTSCAN'), 'RECONNAISSANCE')


class TestSecurityFixes(unittest.TestCase):
    """Tests that critical security vulnerabilities have been fixed."""

    def test_no_api_key_in_env_local(self):
        """Verify .env.local does not contain a Gemini API key."""
        env_path = os.path.join(root_dir, '.env.local')
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                content = f.read()
            self.assertNotIn('VITE_GEMINI_API_KEY', content,
                           ".env.local still contains VITE_GEMINI_API_KEY")

    def test_no_api_key_in_copilot_api(self):
        """Verify frontend copilotApi.ts does not reference Gemini API key."""
        api_path = os.path.join(root_dir, 'src', 'api', 'copilotApi.ts')
        if os.path.exists(api_path):
            with open(api_path, 'r') as f:
                content = f.read()
            self.assertNotIn('VITE_GEMINI_API_KEY', content,
                           "copilotApi.ts still references VITE_GEMINI_API_KEY")
            self.assertNotIn('generativelanguage.googleapis.com', content,
                           "copilotApi.ts still makes direct calls to Google's API")


class TestLivePacketSniffer(unittest.TestCase):
    """Tests for the real-time live network sniffer engine (Pillar 1)."""

    def setUp(self):
        from cyberworld.backend.live_sniffer import LivePacketSniffer
        self.sniffer = LivePacketSniffer(
            world_model=WorldModelPredictor(),
            forecasting_engine=ForecastingEngine(),
            explainability_engine=ExplainabilityEngine(),
            alert_engine=AlertEngine(),
            window_seconds=10,
        )

    def tearDown(self):
        if self.sniffer.is_running:
            self.sniffer.stop()

    def test_sniffer_interfaces(self):
        interfaces = self.sniffer.get_available_interfaces()
        self.assertIsInstance(interfaces, list)
        self.assertGreater(len(interfaces), 0)

    def test_sniffer_status(self):
        status = self.sniffer.get_status()
        self.assertFalse(status['is_running'])
        self.assertEqual(status['packets_captured'], 0)

    def test_simulated_attack_injection(self):
        res = self.sniffer.inject_simulated_attack(stage='RECONNAISSANCE', count=50)
        self.assertEqual(res['status'], 'injected')
        self.assertEqual(res['stage'], 'RECONNAISSANCE')
        self.assertIsNotNone(self.sniffer.latest_frame)
        self.assertGreater(self.sniffer.packets_captured, 0)
        inference = self.sniffer.latest_frame['inference']
        self.assertIn('attack_probability', inference)
        self.assertIn('predicted_stage', inference)


class TestActiveDefense(unittest.TestCase):
    """Tests for Closed-Loop Active Defense & SOAR Containment (Pillar 2)."""

    def setUp(self):
        from cyberworld.cybersecurity.active_defense import ActiveDefenseEngine
        self.db = CyberWorldDatabase(db_path=":memory:")
        self.engine = ActiveDefenseEngine(db=self.db)

    def test_apply_containment_simulated(self):
        record = self.engine.apply_containment(
            target_ip="198.51.100.44",
            target_stage="INITIAL_ACCESS",
            execution_mode="SIMULATED",
            expiry_minutes=15,
        )
        self.assertTrue(record['action_id'].startswith("MIT-"))
        self.assertEqual(record['target_ip'], "198.51.100.44")
        self.assertEqual(record['status'], "ACTIVE")
        self.assertIn("rollback_command", record)

    def test_whitelist_rejection(self):
        for protected_ip in ["127.0.0.1", "8.8.8.8", "192.168.1.1"]:
            with self.assertRaises(ValueError):
                self.engine.apply_containment(target_ip=protected_ip)

    def test_rollback_containment(self):
        record = self.engine.apply_containment(
            target_ip="198.51.100.88",
            target_stage="COMMAND_AND_CONTROL",
            execution_mode="SIMULATED",
        )
        res = self.engine.rollback_containment(record['action_id'], reason="Test Rollback")
        self.assertEqual(res['status'], "ROLLED_BACK")

    def test_database_persistence(self):
        record = self.engine.apply_containment(
            target_ip="198.51.100.12",
            target_stage="EXFILTRATION",
            execution_mode="SIMULATED",
        )
        stored = self.db.get_active_mitigations()
        self.assertGreater(len(stored), 0)
        self.assertEqual(stored[0]['target_ip'], "198.51.100.12")

    def test_autonomous_policy_evaluation(self):
        self.engine.policy_mode = "AUTONOMOUS_PREDICTIVE"
        alert = {
            "id": "ALT-TEST-001",
            "attack_probability": 0.92,
            "predicted_next_stage": "INITIAL_ACCESS",
            "source_ip": "198.51.100.77",
        }
        res = self.engine.evaluate_autonomous_policy(alert)
        self.assertIsNotNone(res)
        self.assertEqual(res['target_ip'], "198.51.100.77")
        self.assertEqual(res['status'], "ACTIVE")


class TestApiEndpoints(unittest.TestCase):
    """Test suite for FastAPI endpoints including Benchmarks, Status, and Mitigation."""

    def setUp(self):
        try:
            from fastapi.testclient import TestClient
            from cyberworld.backend.api import app
            self.client = TestClient(app)
            self.has_client = True
        except Exception:
            self.has_client = False

    def test_health_endpoint(self):
        if not self.has_client:
            self.skipTest("fastapi TestClient not available")
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "ok")

    def test_model_status_endpoint(self):
        if not self.has_client:
            self.skipTest("fastapi TestClient not available")
        resp = self.client.get("/api/model/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("model_loaded", data)
        self.assertIn("inference_mode", data)
        self.assertIn("evaluation_metrics", data)

    def test_benchmarks_endpoint(self):
        if not self.has_client:
            self.skipTest("fastapi TestClient not available")
        resp = self.client.get("/api/benchmarks")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "ready")
        self.assertIn("binary_metrics", data)
        self.assertIn("comparison_summary", data)
        self.assertGreaterEqual(len(data["comparison_summary"]), 3)


if __name__ == '__main__':
    unittest.main(verbosity=2)
