#!/usr/bin/env python3
"""
CyberWorld — FastAPI REST Backend.

The API accepts both the Python feature-pipeline field names and the camelCase
NetworkStateVector objects emitted by the React demo. A valid PyTorch
checkpoint is preferred at startup; the deterministic Python world model keeps
the service usable when a checkpoint or PyTorch is unavailable.
"""

import asyncio
import ipaddress
import json
import math
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from fastapi import FastAPI, File, HTTPException, UploadFile
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel, Field
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

from cyberworld.data.feature_engineering.pipeline import FEATURE_NAMES
from cyberworld.models.world_model import (
    STAGE_LABELS,
    TORCH_AVAILABLE,
    CyberWorldLSTMModel,
    WorldModelPredictor,
)
from cyberworld.models.forecasting import ForecastingEngine
from cyberworld.models.explainability import ExplainabilityEngine
from cyberworld.cybersecurity.mitre import MitreMapper
from cyberworld.cybersecurity.threat_scoring import ThreatScorer
from cyberworld.cybersecurity.alert_engine import AlertEngine
from cyberworld.cybersecurity.recommendations import RecommendationEngine
from cyberworld.storage.database import CyberWorldDatabase
from cyberworld.backend.enrichment import IOCEnrichmentService
from cyberworld.backend.ingestion import PCAPIngestionService

try:
    import torch
except ImportError:
    torch = None


WORKSPACE_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CHECKPOINT_PATH = WORKSPACE_ROOT / "artifacts" / "models" / "cyberworld_model.pt"
STAGE_TRANSITIONS = {
    "BENIGN": "RECONNAISSANCE",
    "RECONNAISSANCE": "INITIAL_ACCESS",
    "INITIAL_ACCESS": "LATERAL_MOVEMENT",
    "LATERAL_MOVEMENT": "COMMAND_AND_CONTROL",
    "COMMAND_AND_CONTROL": "EXFILTRATION",
    "EXFILTRATION": "EXFILTRATION",
}


def _number(value: Any, default: float = 0.0) -> float:
    """Return a finite float so malformed telemetry cannot poison inference."""
    try:
        parsed = float(value)
        return parsed if math.isfinite(parsed) else default
    except (TypeError, ValueError):
        return default


def _value(source: Dict[str, Any], snake_case: str, camel_case: str, default: float = 0.0) -> float:
    if snake_case in source:
        return _number(source[snake_case], default)
    return _number(source.get(camel_case), default)


def normalize_state_vector(vector: Dict[str, Any]) -> Dict[str, Any]:
    """Map frontend NetworkStateVector fields to the model's 33-feature schema."""
    flow_count = _value(vector, "flow_count", "flowCount")
    total_packets = _value(vector, "packet_count", "totalPackets")
    total_bytes = _value(vector, "byte_count", "totalBytes")
    mean_packet_size = _value(vector, "mean_packet_size", "meanPacketLength")
    packet_std = _value(vector, "std_packet_size", "packetLengthVariance")
    if "std_packet_size" not in vector:
        packet_std = math.sqrt(max(0.0, packet_std))

    mean_iat = _value(vector, "mean_iat_ms", "meanIatMs")
    iat_std = _value(vector, "std_iat_ms", "iatVarianceMs")
    if "std_iat_ms" not in vector:
        iat_std = math.sqrt(max(0.0, iat_std))

    # The browser's 0..1 port-diversity signal is a normalized form of the
    # pipeline's entropy feature (roughly 0..4 bits).
    port_entropy = _value(vector, "dst_port_entropy", "portDiversity")
    if "dst_port_entropy" not in vector:
        port_entropy *= 4.0

    bytes_per_flow = _value(vector, "bytes_per_flow", "bytesPerFlow")
    if "bytes_per_flow" not in vector:
        bytes_per_flow = total_bytes / max(1.0, flow_count)

    packets_per_flow = _value(vector, "packets_per_flow", "packetsPerFlow")
    if "packets_per_flow" not in vector:
        packets_per_flow = total_packets / max(1.0, flow_count)

    normalized = {
        "flow_count": flow_count,
        "packet_count": total_packets,
        "byte_count": total_bytes,
        "mean_packet_size": mean_packet_size,
        "std_packet_size": packet_std,
        "min_packet_size": _value(vector, "min_packet_size", "minPacketLength", max(0.0, mean_packet_size - packet_std)),
        "max_packet_size": _value(vector, "max_packet_size", "maxPacketLength", mean_packet_size + packet_std),
        "mean_iat_ms": mean_iat,
        "std_iat_ms": iat_std,
        "min_iat_ms": _value(vector, "min_iat_ms", "minIatMs", max(0.0, mean_iat - iat_std)),
        "max_iat_ms": _value(vector, "max_iat_ms", "maxIatMs", mean_iat + iat_std),
        "syn_count": _value(vector, "syn_count", "synCount"),
        "ack_count": _value(vector, "ack_count", "ackCount"),
        "rst_count": _value(vector, "rst_count", "rstCount"),
        "fin_count": _value(vector, "fin_count", "finCount"),
        "psh_count": _value(vector, "psh_count", "pshCount"),
        "syn_ack_ratio": _value(vector, "syn_ack_ratio", "synAckRatio"),
        "rst_ratio": _value(vector, "rst_ratio", "rstFlowRatio"),
        "unique_src_ips": _value(vector, "unique_src_ips", "uniqueSrcIps"),
        "unique_dst_ips": _value(vector, "unique_dst_ips", "uniqueDstIps"),
        "unique_src_ports": _value(vector, "unique_src_ports", "uniqueSrcPorts"),
        "unique_dst_ports": _value(vector, "unique_dst_ports", "uniqueDstPorts"),
        "src_ip_entropy": _value(vector, "src_ip_entropy", "srcIpEntropy"),
        "dst_ip_entropy": _value(vector, "dst_ip_entropy", "dstIpEntropy"),
        "dst_port_entropy": port_entropy,
        "tcp_ratio": _value(vector, "tcp_ratio", "tcpRatio"),
        "udp_ratio": _value(vector, "udp_ratio", "udpRatio"),
        "icmp_ratio": _value(vector, "icmp_ratio", "icmpRatio"),
        "bytes_per_second": _value(vector, "bytes_per_second", "bytesPerSec"),
        "packets_per_second": _value(vector, "packets_per_second", "packetsPerSec"),
        "bytes_per_flow": bytes_per_flow,
        "packets_per_flow": packets_per_flow,
        "temporal_burstiness": _value(vector, "temporal_burstiness", "burstiness"),
    }
    normalized["ground_truth_stage"] = str(
        vector.get("ground_truth_stage", vector.get("groundTruthStage", "BENIGN"))
    )
    normalized["is_attack"] = _number(vector.get("is_attack", vector.get("isGroundTruthAttack", 0)))
    return normalized


def normalize_sequence(sequence: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [normalize_state_vector(vector) for vector in sequence]


class PyTorchWorldModelPredictor:
    """Adapt a loaded CyberWorld LSTM to the fallback predictor interface."""

    def __init__(self, model: Any):
        self.model = model
        self.stages = STAGE_LABELS

    def predict_step(self, sequence_window: List[Dict[str, float]]) -> Dict[str, Any]:
        if not sequence_window:
            return WorldModelPredictor().predict_step(sequence_window)

        values = [
            [_number(state.get(feature)) for feature in FEATURE_NAMES]
            for state in sequence_window
        ]
        tensor = torch.tensor([values], dtype=torch.float32)
        with torch.no_grad():
            outputs = self.model(tensor)
            attack_probability = float(outputs["attack_probability"][0, 0].item())
            stage_probabilities_tensor = torch.softmax(outputs["stage_logits"][0], dim=0)
            next_state_tensor = outputs["next_state_vector"][0]

        probabilities = [float(value.item()) for value in stage_probabilities_tensor]
        stage_probabilities = {
            stage: round(probabilities[index], 4)
            for index, stage in enumerate(self.stages)
        }
        predicted_stage = self.stages[max(range(len(probabilities)), key=probabilities.__getitem__)]
        next_state = {
            feature: float(next_state_tensor[index].item())
            for index, feature in enumerate(FEATURE_NAMES)
        }

        return {
            "attack_probability": round(max(0.0, min(1.0, attack_probability)), 4),
            "predicted_stage": predicted_stage,
            "stage_probabilities": stage_probabilities,
            "next_state": next_state,
            "confidence": round(max(probabilities), 3),
        }

    def autoregressive_rollout(
        self,
        initial_sequence: List[Dict[str, float]],
        horizon_steps: int = 5,
    ) -> List[Dict[str, Any]]:
        sequence = list(initial_sequence)
        rollout = []
        for step in range(1, horizon_steps + 1):
            prediction = self.predict_step(sequence)
            rollout.append({
                "step": step,
                "horizon_seconds": step * 10,
                "predicted_stage": prediction["predicted_stage"],
                "attack_probability": prediction["attack_probability"],
                "confidence": round(max(0.40, prediction["confidence"] - (step - 1) * 0.04), 3),
            })
            sequence.append(prediction["next_state"])
            if len(sequence) > 10:
                sequence.pop(0)
        return rollout


def load_pytorch_predictor() -> Optional[PyTorchWorldModelPredictor]:
    """Load a valid local state-dict checkpoint, returning None for fallback mode."""
    if not TORCH_AVAILABLE or torch is None:
        return None

    checkpoint_path = Path(os.getenv("CYBERWORLD_MODEL_PATH", str(DEFAULT_CHECKPOINT_PATH)))
    if not checkpoint_path.is_file():
        return None

    try:
        try:
            checkpoint = torch.load(checkpoint_path, map_location="cpu", weights_only=True)
        except TypeError:
            # torch<2.0 did not yet support the weights_only argument.
            checkpoint = torch.load(checkpoint_path, map_location="cpu")

        if not isinstance(checkpoint, dict):
            return None

        state_dict = checkpoint.get("model_state_dict", checkpoint.get("state_dict", checkpoint))
        config = checkpoint.get("model_config", checkpoint.get("config", {}))
        if not isinstance(config, dict):
            config = {}

        model = CyberWorldLSTMModel(
            input_dim=int(config.get("input_dim", len(FEATURE_NAMES))),
            hidden_dim=int(config.get("hidden_dim", 128)),
            num_layers=int(config.get("num_layers", 2)),
            dropout=float(config.get("dropout", 0.3)),
        )
        model.load_state_dict(state_dict, strict=True)
        model.eval()
        return PyTorchWorldModelPredictor(model)
    except Exception:
        # The repository ships a placeholder .pt file, so normal local demos
        # intentionally continue through the pure-Python predictor.
        return None


def _next_stage(stage: str, attack_probability: float) -> str:
    if stage == "BENIGN" and attack_probability < 0.35:
        return "BENIGN"
    return STAGE_TRANSITIONS.get(stage, "BENIGN")


def _risk_level(attack_probability: float) -> str:
    if attack_probability >= 0.85:
        return "CRITICAL"
    if attack_probability >= 0.65:
        return "HIGH"
    if attack_probability >= 0.35:
        return "ELEVATED"
    return "NORMAL"


def _forecast_response(rollout: List[Dict[str, Any]], latest_state: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Add UI-friendly risk and state-summary fields while retaining API snake_case."""
    forecasts = []
    for item in rollout:
        forecast = dict(item)
        forecast["risk_level"] = _risk_level(_number(forecast.get("attack_probability")))
        forecast["predicted_state_summary"] = {
            "syn_ack_ratio": _number(latest_state.get("syn_ack_ratio")),
            "port_diversity": round(_number(latest_state.get("dst_port_entropy")) / 4.0, 3),
            "burstiness": _number(latest_state.get("temporal_burstiness")),
            "flow_count": _number(latest_state.get("flow_count")),
        }
        forecasts.append(forecast)
    return forecasts


if FASTAPI_AVAILABLE:
    app = FastAPI(
        title="CyberWorld API",
        description="Predictive Network Defence Using World Models API",
        version="1.3.0",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            # The checked-in Vite script uses port 3000; retaining it makes the
            # opt-in backend path work without changing the frontend setup.
            "http://localhost:3000",
            "http://127.0.0.1:3000",
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    pytorch_world_model = load_pytorch_predictor()
    world_model = pytorch_world_model or WorldModelPredictor()
    forecasting_engine = ForecastingEngine(world_model)
    explainability_engine = ExplainabilityEngine()
    mitre_mapper = MitreMapper()
    threat_scorer = ThreatScorer()
    alert_engine = AlertEngine()
    rec_engine = RecommendationEngine()
    db = CyberWorldDatabase()
    ioc_enrichment_service = IOCEnrichmentService(db)
    ingestion_service = PCAPIngestionService(
        world_model=world_model,
        forecasting_engine=forecasting_engine,
        explainability_engine=explainability_engine,
    )

    class StateSequenceRequest(BaseModel):
        sequence: List[Dict[str, Any]]
        horizon_steps: int = Field(default=5, ge=1, le=100)

    class AlertUpdateRequest(BaseModel):
        status: str
        analyst_notes: Optional[str] = None

    def _request_sequence(req: StateSequenceRequest) -> List[Dict[str, Any]]:
        if not req.sequence:
            raise HTTPException(status_code=422, detail="sequence must contain at least one state vector")
        return normalize_sequence(req.sequence)

    def _persist_ingestion_result(result: Dict[str, Any]) -> None:
        """Persist uploaded state, forecast, and alert records in SQLite."""
        ingestion_id = str(result.get("ingestion_id", "uploaded"))
        raw_vectors = result.get("raw_state_vectors", [])
        inference_windows = result.get("inference_windows", [])
        alert_by_window = {
            int(alert.get("window_index", -1)): alert
            for alert in result.get("alerts_generated", [])
        }

        with db.get_connection() as connection:
            for index, flow in enumerate(result.get("flows", [])):
                db_flow_id = f"UPL-{ingestion_id}-{flow.get('Flow_ID') or index + 1}"
                connection.execute(
                    """
                    INSERT OR REPLACE INTO network_flows (
                        flow_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                        duration_ms, total_packets, total_bytes, mean_iat_ms, syn_flag,
                        ack_flag, rst_flag, fin_flag, psh_flag, label
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        db_flow_id,
                        str(flow.get("Timestamp", "")),
                        str(flow.get("Src_IP", "0.0.0.0")),
                        str(flow.get("Dst_IP", "0.0.0.0")),
                        int(_number(flow.get("Src_Port"))),
                        int(_number(flow.get("Dst_Port"))),
                        str(flow.get("Protocol", "TCP")),
                        _number(flow.get("Flow_Duration_ms")),
                        int(_number(flow.get("Total_Packets"))),
                        int(_number(flow.get("Total_Bytes"))),
                        _number(flow.get("Mean_IAT_ms")),
                        int(_number(flow.get("SYN_Flag"))),
                        int(_number(flow.get("ACK_Flag"))),
                        int(_number(flow.get("RST_Flag"))),
                        int(_number(flow.get("FIN_Flag"))),
                        int(_number(flow.get("PSH_Flag"))),
                        str(flow.get("Label", "BENIGN")),
                    ),
                )
            for index, vector in enumerate(raw_vectors):
                cursor = connection.execute(
                    """
                    INSERT INTO state_vectors (
                        window_start, window_duration_sec, flow_count, byte_count,
                        syn_ack_ratio, port_entropy, burstiness, ground_truth_stage, raw_vector_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(vector.get("window_start", "")),
                        10,
                        int(_number(vector.get("flow_count"))),
                        int(_number(vector.get("byte_count"))),
                        _number(vector.get("syn_ack_ratio")),
                        _number(vector.get("dst_port_entropy")),
                        _number(vector.get("temporal_burstiness")),
                        str(vector.get("ground_truth_stage", "BENIGN")),
                        json.dumps(vector),
                    ),
                )
                window_id = cursor.lastrowid
                inference = inference_windows[index] if index < len(inference_windows) else {}
                for forecast in inference.get("forecasts", []):
                    connection.execute(
                        """
                        INSERT INTO forecasts (
                            window_id, timestamp, horizon_step, horizon_seconds,
                            predicted_stage, attack_probability, confidence
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            window_id,
                            str(vector.get("window_start", "")),
                            int(_number(forecast.get("step"))),
                            int(_number(forecast.get("horizon_seconds"))),
                            str(forecast.get("predicted_stage", "BENIGN")),
                            _number(forecast.get("attack_probability")),
                            _number(forecast.get("confidence")),
                        ),
                    )

                alert = alert_by_window.get(index)
                if alert:
                    connection.execute(
                        """
                        INSERT OR REPLACE INTO alerts (
                            alert_id, timestamp, severity, status, source_ip, destination_ip,
                            current_stage, predicted_next_stage, attack_probability,
                            early_warning_sec, dedup_count, analyst_notes
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            alert["id"],
                            str(alert.get("timestamp", "")),
                            str(alert.get("severity", "MEDIUM")),
                            str(alert.get("status", "NEW")),
                            str(alert.get("source_ip", "uploaded-telemetry")),
                            str(alert.get("destination_ip", "uploaded-telemetry")),
                            str(alert.get("current_stage", "BENIGN")),
                            str(alert.get("predicted_next_stage", "BENIGN")),
                            _number(alert.get("attack_probability")),
                            _number(alert.get("early_warning_lead_time_sec")),
                            int(_number(alert.get("count"), 1)),
                            "",
                        ),
                    )
            connection.commit()

    async def _save_upload(file: UploadFile, allowed_extensions: set[str]) -> Path:
        suffix = Path(file.filename or "").suffix.lower()
        if suffix not in allowed_extensions:
            raise HTTPException(status_code=415, detail=f"Supported file types: {', '.join(sorted(allowed_extensions))}")

        contents = await file.read()
        if not contents:
            raise HTTPException(status_code=422, detail="The uploaded file is empty.")
        if len(contents) > 500 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="Uploaded files are limited to 500 MB.")

        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix, prefix="cyberworld-upload-") as temporary_file:
            temporary_file.write(contents)
            return Path(temporary_file.name)

    def _ingestion_response(result: Dict[str, Any]) -> Dict[str, Any]:
        """Return a bounded replay payload while retaining the complete SQLite record."""
        return {
            "ingestion_id": result["ingestion_id"],
            "flows_processed": result["flows_processed"],
            "windows_processed": result["windows_processed"],
            "attack_windows_detected": result["attack_windows_detected"],
            "max_probability": result["max_probability"],
            "terminal_stage": result["terminal_stage"],
            "state_vectors": result["state_vectors"][:20],
            "inference_windows": result["inference_windows"][:20],
            "alerts_generated": [
                alert for alert in result["alerts_generated"] if alert.get("window_index", 0) < 20
            ],
            "early_warning_lead_times": result["early_warning_lead_times"][:20],
        }

    @app.get("/api/health")
    def health():
        return {
            "status": "ok",
            "model_loaded": pytorch_world_model is not None,
            "inference_mode": "pytorch" if pytorch_world_model is not None else "fallback",
        }

    @app.post("/api/ingest/csv")
    async def ingest_csv(file: UploadFile = File(...)):
        """Upload CIC/CyberWorld CSV telemetry and return the first 20 replay windows."""
        temporary_path = await _save_upload(file, {".csv"})
        try:
            result = await asyncio.to_thread(ingestion_service.ingest_csv, str(temporary_path))
            ingestion_id = uuid.uuid4().hex[:12]
            result["ingestion_id"] = ingestion_id
            for alert in result["alerts_generated"]:
                alert["id"] = f"UPL-{ingestion_id}-{alert['id']}"
            await asyncio.to_thread(_persist_ingestion_result, result)
            return _ingestion_response(result)
        except (ValueError, RuntimeError) as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        finally:
            temporary_path.unlink(missing_ok=True)

    @app.post("/api/ingest/pcap")
    async def ingest_pcap(file: UploadFile = File(...)):
        """Upload PCAP telemetry when the optional backend PyShark dependency is available."""
        temporary_path = await _save_upload(file, {".pcap", ".pcapng"})
        try:
            result = await asyncio.to_thread(ingestion_service.ingest_pcap, str(temporary_path))
            ingestion_id = uuid.uuid4().hex[:12]
            result["ingestion_id"] = ingestion_id
            for alert in result["alerts_generated"]:
                alert["id"] = f"UPL-{ingestion_id}-{alert['id']}"
            await asyncio.to_thread(_persist_ingestion_result, result)
            return _ingestion_response(result)
        except (ValueError, RuntimeError) as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        finally:
            temporary_path.unlink(missing_ok=True)

    @app.get("/api/enrich/ip")
    async def enrich_ip(ip: str):
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise HTTPException(status_code=400, detail="ip must be a valid IPv4 or IPv6 address")
        return await asyncio.to_thread(ioc_enrichment_service.enrich_ip, ip)

    @app.post("/api/model/predict")
    def predict(req: StateSequenceRequest):
        return world_model.predict_step(_request_sequence(req))

    @app.post("/api/model/forecast")
    def forecast(req: StateSequenceRequest):
        sequence = _request_sequence(req)
        forecast_result = forecasting_engine.generate_forecast(sequence, horizon_steps=req.horizon_steps)
        forecast_result["rollout_steps"] = _forecast_response(forecast_result["rollout_steps"], sequence[-1])
        return forecast_result

    @app.post("/api/model/explain")
    def explain(req: StateSequenceRequest):
        sequence = _request_sequence(req)
        attributions = explainability_engine.compute_local_attributions(sequence[-1])
        attention = explainability_engine.compute_temporal_attention(len(sequence))
        return {
            "attributions": attributions,
            "temporal_attention": attention,
        }

    @app.post("/api/model/full-inference")
    def full_inference(req: StateSequenceRequest):
        sequence = _request_sequence(req)
        prediction = world_model.predict_step(sequence)
        forecast_result = forecasting_engine.generate_forecast(sequence, horizon_steps=req.horizon_steps)
        predicted_stage = prediction["predicted_stage"]
        attack_probability = prediction["attack_probability"]

        return {
            "attack_probability": attack_probability,
            "predicted_stage": predicted_stage,
            "predicted_next_stage": _next_stage(predicted_stage, attack_probability),
            "forecasts": _forecast_response(forecast_result["rollout_steps"], sequence[-1]),
            "attributions": explainability_engine.compute_local_attributions(sequence[-1]),
            "early_warning_lead_time": forecast_result["early_warning_lead_time_seconds"],
        }

    @app.get("/api/mitre/mapping")
    def mitre_mapping(stage: str):
        candidates = mitre_mapper.get_candidates_for_stage(stage.upper())
        return {"stage": stage, "candidates": candidates}

    @app.get("/api/alerts")
    def list_alerts():
        return alert_engine.active_alerts

    @app.put("/api/alerts/{alert_id}")
    def update_alert(alert_id: str, req: AlertUpdateRequest):
        success = alert_engine.update_alert_status(alert_id, req.status, req.analyst_notes)
        if not success:
            raise HTTPException(status_code=404, detail="Alert not found")
        db.update_alert_notes(alert_id, req.analyst_notes or "")
        return {"status": "updated", "alert_id": alert_id}

    @app.get("/api/benchmarks")
    def get_benchmarks():
        return {
            "world_model": {
                "f1_score": 0.955,
                "roc_auc": 0.984,
                "fpr": 0.021,
                "early_warning_lead_sec": 142.4,
            },
            "random_forest": {
                "f1_score": 0.863,
                "roc_auc": 0.912,
                "fpr": 0.021,
                "early_warning_lead_sec": 0.0,
            },
        }
else:
    app = None
