"""CSV and optional PCAP ingestion for the CyberWorld inference pipeline."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import pandas as pd

from cyberworld.data.feature_engineering.pipeline import NetworkFeaturePipeline
from cyberworld.models.explainability import ExplainabilityEngine
from cyberworld.models.forecasting import ForecastingEngine
from cyberworld.models.world_model import WorldModelPredictor


STAGE_TRANSITIONS = {
    "BENIGN": "RECONNAISSANCE",
    "RECONNAISSANCE": "INITIAL_ACCESS",
    "INITIAL_ACCESS": "LATERAL_MOVEMENT",
    "LATERAL_MOVEMENT": "COMMAND_AND_CONTROL",
    "COMMAND_AND_CONTROL": "EXFILTRATION",
    "EXFILTRATION": "EXFILTRATION",
}


def _normalized_column_name(value: Any) -> str:
    return "".join(character for character in str(value).strip().lower() if character.isalnum())


def _number(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
        return number if math.isfinite(number) else default
    except (TypeError, ValueError):
        return default


def _protocol(value: Any) -> str:
    numeric_protocols = {6: "TCP", 17: "UDP", 1: "ICMP"}
    numeric = _number(value, -1)
    if numeric in numeric_protocols:
        return numeric_protocols[int(numeric)]
    text = str(value or "TCP").upper()
    return text if text in {"TCP", "UDP", "ICMP"} else "TCP"


def _stage_from_label(value: Any) -> str:
    label = str(value or "BENIGN").strip().upper().replace(" ", "_").replace("-", "_")
    if label in STAGE_TRANSITIONS:
        return label
    if not label or label in {"BENIGN", "NORMAL", "0"}:
        return "BENIGN"
    if "PORT" in label and "SCAN" in label:
        return "RECONNAISSANCE"
    if any(token in label for token in ("BRUTE", "WEB_ATTACK", "FTP", "SSH", "PASSWORD")):
        return "INITIAL_ACCESS"
    if any(token in label for token in ("INFILTRATION", "LATERAL", "PIVOT")):
        return "LATERAL_MOVEMENT"
    if any(token in label for token in ("BOT", "C2", "COMMAND", "CONTROL")):
        return "COMMAND_AND_CONTROL"
    if any(token in label for token in ("EXFIL", "HEARTBLEED")):
        return "EXFILTRATION"
    # CIC labels such as DoS/DDoS have no direct ATT&CK phase. They remain
    # attack-labelled and use INITIAL_ACCESS as the conservative default stage.
    return "INITIAL_ACCESS"


class PCAPIngestionService:
    """Ingests flow records and runs the real CyberWorld inference stack."""

    def __init__(
        self,
        world_model: Optional[Any] = None,
        forecasting_engine: Optional[ForecastingEngine] = None,
        explainability_engine: Optional[ExplainabilityEngine] = None,
        window_seconds: int = 10,
    ) -> None:
        self.pipeline = NetworkFeaturePipeline(window_seconds=window_seconds)
        self.world_model = world_model or WorldModelPredictor()
        self.forecasting_engine = forecasting_engine or ForecastingEngine(self.world_model)
        self.explainability_engine = explainability_engine or ExplainabilityEngine()

    def ingest_csv(self, csv_path: str) -> Dict[str, Any]:
        """
        Accepts CICIDS-2017/CIC-IDS-2018 exports or CyberWorld sample CSVs.

        The service normalizes export-specific headers, constructs chronological
        state vectors, executes inference for every window, and returns both a
        compact frontend representation and raw vectors for SQLite persistence.
        """
        source_path = Path(csv_path)
        if not source_path.is_file():
            raise FileNotFoundError(f"CSV file was not found: {source_path}")

        frame = pd.read_csv(source_path, low_memory=False)
        if frame.empty:
            raise ValueError("The uploaded CSV contains no flow records.")

        flows = self._normalize_csv_frame(frame)
        return self._run_inference(flows)

    def ingest_pcap(self, pcap_path: str) -> Dict[str, Any]:
        """Convert a PCAP into packet-flows when optional PyShark is installed."""
        try:
            import pyshark  # type: ignore[import-not-found]
        except ImportError as error:
            raise RuntimeError(
                "PCAP ingestion requires the optional pyshark dependency on the backend."
            ) from error

        capture = pyshark.FileCapture(pcap_path, keep_packets=False)
        flows: List[Dict[str, Any]] = []
        try:
            for index, packet in enumerate(capture):
                if not hasattr(packet, "ip"):
                    continue
                protocol = _protocol(getattr(packet, "transport_layer", "TCP"))
                transport = getattr(packet, protocol.lower(), None)
                flags = str(getattr(transport, "flags", "")) if transport else ""
                flows.append({
                    "Flow_ID": f"PCAP-{index}",
                    "Timestamp": str(getattr(packet, "sniff_time", "")),
                    "Src_IP": str(packet.ip.src),
                    "Dst_IP": str(packet.ip.dst),
                    "Src_Port": _number(getattr(transport, "srcport", 0)),
                    "Dst_Port": _number(getattr(transport, "dstport", 0)),
                    "Protocol": protocol,
                    "Flow_Duration_ms": 0,
                    "Total_Packets": 1,
                    "Total_Bytes": _number(getattr(packet, "length", 0)),
                    "Mean_IAT_ms": 0,
                    "SYN_Flag": int("0x0002" in flags),
                    "ACK_Flag": int("0x0010" in flags),
                    "RST_Flag": int("0x0004" in flags),
                    "FIN_Flag": int("0x0001" in flags),
                    "PSH_Flag": int("0x0008" in flags),
                    "TTL": _number(getattr(packet.ip, "ttl", 64), 64),
                    "Payload_Entropy": 0,
                    "Is_Attack": 0,
                    "Label": "BENIGN",
                })
        finally:
            capture.close()

        if not flows:
            raise ValueError("No IPv4/IPv6 packets were found in the uploaded PCAP.")
        return self._run_inference(flows)

    def _normalize_csv_frame(self, frame: pd.DataFrame) -> List[Dict[str, Any]]:
        aliases = {
            "flowid": "Flow_ID",
            "timestamp": "Timestamp",
            "sourceip": "Src_IP",
            "srcip": "Src_IP",
            "destinationip": "Dst_IP",
            "dstip": "Dst_IP",
            "sourceport": "Src_Port",
            "srcport": "Src_Port",
            "destinationport": "Dst_Port",
            "dstport": "Dst_Port",
            "protocol": "Protocol",
            "flowdurationms": "Flow_Duration_ms",
            "flowduration": "__flow_duration_microseconds",
            "totalpackets": "Total_Packets",
            "totfwdpkts": "__forward_packets",
            "totalfwdpackets": "__forward_packets",
            "totbwdpkts": "__backward_packets",
            "totalbackwardpackets": "__backward_packets",
            "totalbytes": "Total_Bytes",
            "totlenfwdpkts": "__forward_bytes",
            "totallengthoffwdpackets": "__forward_bytes",
            "totallengthofforwardpackets": "__forward_bytes",
            "totlenbwdpkts": "__backward_bytes",
            "totallengthofbwdpackets": "__backward_bytes",
            "totallengthofbackwardpackets": "__backward_bytes",
            "bytesperpacket": "Bytes_Per_Packet",
            "flowiatmean": "__iat_microseconds",
            "meaniatms": "Mean_IAT_ms",
            "synflag": "SYN_Flag",
            "synflagcnt": "SYN_Flag",
            "synflagcount": "SYN_Flag",
            "ackflag": "ACK_Flag",
            "ackflagcnt": "ACK_Flag",
            "ackflagcount": "ACK_Flag",
            "rstflag": "RST_Flag",
            "rstflagcnt": "RST_Flag",
            "rstflagcount": "RST_Flag",
            "finflag": "FIN_Flag",
            "finflagcnt": "FIN_Flag",
            "finflagcount": "FIN_Flag",
            "pshflag": "PSH_Flag",
            "pshflagcnt": "PSH_Flag",
            "pshflagcount": "PSH_Flag",
            "ttl": "TTL",
            "label": "Label",
            "isattack": "Is_Attack",
        }
        renamed = frame.rename(columns={
            column: aliases.get(_normalized_column_name(column), str(column).strip())
            for column in frame.columns
        }).copy()

        if "Timestamp" not in renamed.columns:
            raise ValueError("A Timestamp column is required for chronological ingestion.")

        def values(*columns: str, default: float = 0.0) -> pd.Series:
            for column in columns:
                if column in renamed.columns:
                    return pd.to_numeric(renamed[column], errors="coerce").fillna(default)
            return pd.Series(default, index=renamed.index, dtype="float64")

        if "Total_Packets" not in renamed.columns:
            renamed["Total_Packets"] = values("__forward_packets") + values("__backward_packets")
        if "Total_Bytes" not in renamed.columns:
            renamed["Total_Bytes"] = values("__forward_bytes") + values("__backward_bytes")
        if "Mean_IAT_ms" not in renamed.columns:
            renamed["Mean_IAT_ms"] = values("__iat_microseconds") / 1000.0
        if "Flow_Duration_ms" not in renamed.columns:
            renamed["Flow_Duration_ms"] = values("__flow_duration_microseconds") / 1000.0
        if "Bytes_Per_Packet" not in renamed.columns:
            renamed["Bytes_Per_Packet"] = values("Total_Bytes") / values("Total_Packets", default=1.0).clip(lower=1)

        defaults: Dict[str, Any] = {
            "Flow_ID": "",
            "Src_IP": "0.0.0.0",
            "Dst_IP": "0.0.0.0",
            "Src_Port": 0,
            "Dst_Port": 0,
            "Protocol": "TCP",
            "SYN_Flag": 0,
            "ACK_Flag": 0,
            "RST_Flag": 0,
            "FIN_Flag": 0,
            "PSH_Flag": 0,
            "TTL": 64,
            "Payload_Entropy": 0,
            "Label": "BENIGN",
            "Is_Attack": 0,
        }
        for column, default in defaults.items():
            if column not in renamed.columns:
                renamed[column] = default

        flows: List[Dict[str, Any]] = []
        numeric_columns = {
            "Src_Port", "Dst_Port", "Flow_Duration_ms", "Total_Packets", "Total_Bytes",
            "Bytes_Per_Packet", "Mean_IAT_ms", "SYN_Flag", "ACK_Flag", "RST_Flag",
            "FIN_Flag", "PSH_Flag", "TTL", "Payload_Entropy",
        }
        for index, row in enumerate(renamed.to_dict(orient="records")):
            label = _stage_from_label(row.get("Label"))
            flows.append({
                "Flow_ID": str(row.get("Flow_ID") or f"UPL-{index + 1}"),
                "Timestamp": str(row.get("Timestamp") or ""),
                "Src_IP": str(row.get("Src_IP") or "0.0.0.0"),
                "Dst_IP": str(row.get("Dst_IP") or "0.0.0.0"),
                "Protocol": _protocol(row.get("Protocol")),
                "Label": label,
                "Is_Attack": int(label != "BENIGN"),
                **{
                    column: _number(row.get(column), 0.0 if column != "TTL" else 64.0)
                    for column in numeric_columns
                },
            })
        return flows

    def _run_inference(self, flows: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        flow_list = list(flows)
        state_vectors = self.pipeline.process_flow_sequence(flow_list)
        if not state_vectors:
            raise ValueError("No chronological state vectors could be generated from the upload.")

        inference_windows: List[Dict[str, Any]] = []
        alerts_generated: List[Dict[str, Any]] = []
        early_warning_lead_times: List[float] = []
        frontend_vectors: List[Dict[str, Any]] = []
        max_probability = 0.0

        for index, state_vector in enumerate(state_vectors):
            sequence = state_vectors[max(0, index - 9): index + 1]
            prediction = self.world_model.predict_step(sequence)
            forecast = self.forecasting_engine.generate_forecast(sequence, horizon_steps=10)
            probability = _number(prediction.get("attack_probability"))
            predicted_stage = str(prediction.get("predicted_stage", "BENIGN"))
            lead_time = _number(forecast.get("early_warning_lead_time_seconds"))
            max_probability = max(max_probability, probability)
            early_warning_lead_times.append(lead_time)

            inference_windows.append({
                "window_index": index,
                "attack_probability": round(probability, 4),
                "predicted_stage": predicted_stage,
                "predicted_next_stage": STAGE_TRANSITIONS.get(predicted_stage, "BENIGN"),
                "confidence": _number(prediction.get("confidence")),
                "forecasts": forecast.get("rollout_steps", []),
                "attributions": self.explainability_engine.compute_local_attributions(state_vector),
                "early_warning_lead_time": lead_time,
            })
            frontend_vectors.append(self._frontend_vector(state_vector, index))

            if probability >= 0.35:
                alerts_generated.append({
                    "id": f"UPL-ALT-{index + 1:05d}",
                    "window_index": index,
                    "timestamp": state_vector.get("window_start", ""),
                    "severity": self._severity(probability),
                    "status": "NEW",
                    "source_ip": "uploaded-telemetry",
                    "destination_ip": "uploaded-telemetry",
                    "current_stage": predicted_stage,
                    "predicted_next_stage": STAGE_TRANSITIONS.get(predicted_stage, "BENIGN"),
                    "attack_probability": round(probability, 4),
                    "early_warning_lead_time_sec": lead_time,
                    "count": int(state_vector.get("flow_count", 0)),
                })

        terminal_stage = inference_windows[-1]["predicted_stage"]
        return {
            "flows": flow_list,
            "flows_processed": len(flow_list),
            "windows_processed": len(state_vectors),
            "attack_windows_detected": sum(item["attack_probability"] >= 0.35 for item in inference_windows),
            "max_probability": round(max_probability, 4),
            "terminal_stage": terminal_stage,
            "state_vectors": frontend_vectors,
            "raw_state_vectors": state_vectors,
            "inference_windows": inference_windows,
            "alerts_generated": alerts_generated,
            "early_warning_lead_times": early_warning_lead_times,
        }

    @staticmethod
    def _severity(probability: float) -> str:
        if probability >= 0.85:
            return "CRITICAL"
        if probability >= 0.65:
            return "HIGH"
        if probability >= 0.35:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _frontend_vector(vector: Dict[str, Any], index: int) -> Dict[str, Any]:
        packet_count = _number(vector.get("packet_count"))
        byte_count = _number(vector.get("byte_count"))
        flow_count = _number(vector.get("flow_count"))
        mean_packet_size = _number(vector.get("mean_packet_size"))
        std_packet_size = _number(vector.get("std_packet_size"))
        mean_iat = _number(vector.get("mean_iat_ms"))
        std_iat = _number(vector.get("std_iat_ms"))
        stage = _stage_from_label(vector.get("ground_truth_stage"))

        return {
            "windowIndex": index,
            "timestamp": str(vector.get("window_start", "")),
            "timeOffsetSeconds": index * 10,
            "flowCount": int(flow_count),
            "totalBytes": int(byte_count),
            "totalPackets": int(packet_count),
            "packetsPerSec": round(_number(vector.get("packets_per_second")), 2),
            "bytesPerSec": round(_number(vector.get("bytes_per_second")), 2),
            "bytesPerPacket": round(byte_count / max(1.0, packet_count), 2),
            "tcpRatio": _number(vector.get("tcp_ratio")),
            "udpRatio": _number(vector.get("udp_ratio")),
            "icmpRatio": _number(vector.get("icmp_ratio")),
            "synCount": int(_number(vector.get("syn_count"))),
            "ackCount": int(_number(vector.get("ack_count"))),
            "rstCount": int(_number(vector.get("rst_count"))),
            "finCount": int(_number(vector.get("fin_count"))),
            "pshCount": int(_number(vector.get("psh_count"))),
            "synAckRatio": _number(vector.get("syn_ack_ratio")),
            "rstFlowRatio": _number(vector.get("rst_ratio")),
            "uniqueSrcIps": int(_number(vector.get("unique_src_ips"))),
            "uniqueDstIps": int(_number(vector.get("unique_dst_ips"))),
            "uniqueDstPorts": int(_number(vector.get("unique_dst_ports"))),
            "portDiversity": round(min(1.0, _number(vector.get("dst_port_entropy")) / 4.0), 3),
            "srcDstConcentration": round(1.0 / max(1.0, _number(vector.get("unique_dst_ips"))), 3),
            "meanDurationMs": round(mean_iat, 2),
            "meanIatMs": round(mean_iat, 2),
            "iatVarianceMs": round(std_iat ** 2, 2),
            "burstiness": _number(vector.get("temporal_burstiness")),
            "meanPacketLength": round(mean_packet_size, 2),
            "packetLengthVariance": round(std_packet_size ** 2, 2),
            "packetSizeEntropy": round(_number(vector.get("dst_port_entropy")), 2),
            "meanTtl": 64,
            "ttlVariance": 0,
            "groundTruthStage": stage,
            "isGroundTruthAttack": stage != "BENIGN",
        }
