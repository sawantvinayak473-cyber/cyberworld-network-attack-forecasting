#!/usr/bin/env python3
"""
CyberWorld — Real-Time Live Network Sniffer & Sensor Engine.

Captures live IP packets via Scapy / raw sockets on active network adapters,
aggregates traffic into tumbling temporal windows (10-second default), extracts the
33-dimensional CyberWorld state vector S(t), runs real-time PyTorch World Model
forecasting, and streams telemetry to connected SOC dashboard clients.
"""

import asyncio
import datetime
import logging
import math
import random
import threading
import time
from collections import deque
from typing import Any, Callable, Dict, List, Optional, Set

try:
    from scapy.all import IP, IPv6, TCP, UDP, ICMP, conf, get_if_list, sniff
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from cyberworld.data.feature_engineering.pipeline import FEATURE_NAMES, NetworkFeaturePipeline

logger = logging.getLogger("cyberworld_sniffer")


class LivePacketSniffer:
    """
    Continuous network telemetry sensor that sniffs real packets, extracts 33-dim
    feature vectors, evaluates World Model inference, and streams updates.
    """

    def __init__(
        self,
        world_model: Any,
        forecasting_engine: Any,
        explainability_engine: Any,
        alert_engine: Any,
        window_seconds: int = 10,
        sequence_length: int = 10,
        interface: Optional[str] = None,
    ):
        self.world_model = world_model
        self.forecasting_engine = forecasting_engine
        self.explainability_engine = explainability_engine
        self.alert_engine = alert_engine
        self.window_seconds = window_seconds
        self.sequence_length = sequence_length
        self.interface = interface

        self.pipeline = NetworkFeaturePipeline(window_seconds=window_seconds)

        # Threading & lifecycle flags
        self.is_running = False
        self._stop_requested = False
        self._sniff_thread: Optional[threading.Thread] = None
        self._window_timer_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Telemetry metrics
        self.packets_captured = 0
        self.bytes_captured = 0
        self.flows_captured = 0
        self.start_time: Optional[float] = None
        self.last_packet_time: float = time.time()

        # Window buffers
        self._current_window_flows: List[Dict[str, Any]] = []
        self._current_window_start: datetime.datetime = datetime.datetime.now()
        self.history_sequence: deque[Dict[str, Any]] = deque(maxlen=sequence_length)
        self.recent_windows: deque[Dict[str, Any]] = deque(maxlen=60)

        # Latest published inference frame
        self.latest_frame: Optional[Dict[str, Any]] = None

        # WebSocket subscribers (async event broadcast)
        self._subscribers: Set[asyncio.Queue] = set()

    def get_available_interfaces(self) -> List[Dict[str, str]]:
        """List all active and virtual network adapters available for sniffing."""
        if not SCAPY_AVAILABLE:
            return [{"id": "fallback_sim", "name": "Fallback Traffic Simulator"}]
        try:
            raw_interfaces = get_if_list()
            interfaces = []
            for iface in raw_interfaces:
                name = str(iface)
                if "Loopback" in name:
                    desc = "Loopback (Localhost Testing)"
                elif "{" in name:
                    desc = f"Network Adapter ({name[-8:-1]})"
                else:
                    desc = name
                interfaces.append({"id": name, "name": desc})
            return interfaces
        except Exception as e:
            logger.error(f"Error enumerating interfaces: {e}")
            return [{"id": "default", "name": "Default Route Adapter"}]

    def start(self, interface: Optional[str] = None):
        """Start the live sniffing background thread."""
        with self._lock:
            if self.is_running:
                logger.warning("Sniffer already running.")
                return

            if interface:
                self.interface = interface
            elif not self.interface and SCAPY_AVAILABLE:
                try:
                    self.interface = conf.iface
                except Exception:
                    self.interface = None

            self.is_running = True
            self._stop_requested = False
            self.start_time = time.time()
            self._current_window_start = datetime.datetime.now()
            self._current_window_flows = []

            # Launch packet capture thread
            self._sniff_thread = threading.Thread(
                target=self._run_packet_capture,
                name="CyberWorld-Sniffer-Capture",
                daemon=True,
            )
            self._sniff_thread.start()

            # Launch tumbling window evaluation thread
            self._window_timer_thread = threading.Thread(
                target=self._run_window_evaluator,
                name="CyberWorld-Sniffer-Evaluator",
                daemon=True,
            )
            self._window_timer_thread.start()

            logger.info(f"Live network sniffer started on interface: {self.interface or 'DEFAULT'}")

    def stop(self):
        """Gracefully stop packet sniffing."""
        with self._lock:
            if not self.is_running:
                return
            self._stop_requested = True
            self.is_running = False

        if self._sniff_thread and self._sniff_thread.is_alive():
            self._sniff_thread.join(timeout=1.5)
        if self._window_timer_thread and self._window_timer_thread.is_alive():
            self._window_timer_thread.join(timeout=1.5)

        logger.info("Live network sniffer stopped.")

    def _run_packet_capture(self):
        """Packet capture loop running on worker thread."""
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available. Running in synthetic baseline sensor mode.")
            self._run_fallback_generator()
            return

        try:
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda p: self._stop_requested,
            )
        except Exception as e:
            logger.error(f"Error in Scapy live capture: {e}. Falling back to baseline sensor.")
            self._run_fallback_generator()

    def _process_packet(self, packet):
        """Parse raw Ethernet/IP packet into a normalized flow record."""
        if self._stop_requested:
            return

        now = time.time()
        iat_ms = (now - self.last_packet_time) * 1000.0
        self.last_packet_time = now

        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        protocol = "OTHER"
        src_port = 0
        dst_port = 0
        syn = ack = rst = fin = psh = 0

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        elif IPv6 in packet:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst

        pkt_len = len(packet)

        if TCP in packet:
            protocol = "TCP"
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
            flags = packet[TCP].flags
            # Scapy flag checks
            syn = 1 if flags & 0x02 else 0
            ack = 1 if flags & 0x10 else 0
            rst = 1 if flags & 0x04 else 0
            fin = 1 if flags & 0x01 else 0
            psh = 1 if flags & 0x08 else 0
        elif UDP in packet:
            protocol = "UDP"
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)
        elif ICMP in packet:
            protocol = "ICMP"

        flow_record = {
            "Timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "Src_IP": src_ip,
            "Dst_IP": dst_ip,
            "Src_Port": src_port,
            "Dst_Port": dst_port,
            "Protocol": protocol,
            "Total_Packets": 1,
            "Total_Bytes": pkt_len,
            "Mean_IAT_ms": max(0.1, round(iat_ms, 2)),
            "SYN_Flag": syn,
            "ACK_Flag": ack,
            "RST_Flag": rst,
            "FIN_Flag": fin,
            "PSH_Flag": psh,
            "Label": "BENIGN",
        }

        with self._lock:
            self.packets_captured += 1
            self.bytes_captured += pkt_len
            self._current_window_flows.append(flow_record)

    def _run_fallback_generator(self):
        """Simulate lightweight benign background telemetry if raw sockets are restricted."""
        while not self._stop_requested:
            # Emit 1 to 5 normal background packets per interval
            time.sleep(random.uniform(0.1, 0.4))
            now = time.time()
            flow_record = {
                "Timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                "Src_IP": f"192.168.1.{random.randint(10, 50)}",
                "Dst_IP": random.choice(["142.250.190.46", "1.1.1.1", "10.0.0.1"]),
                "Src_Port": random.randint(49152, 65535),
                "Dst_Port": random.choice([80, 443, 53]),
                "Protocol": "TCP" if random.random() < 0.85 else "UDP",
                "Total_Packets": random.randint(1, 4),
                "Total_Bytes": random.randint(60, 450),
                "Mean_IAT_ms": random.uniform(15.0, 120.0),
                "SYN_Flag": 1 if random.random() < 0.1 else 0,
                "ACK_Flag": 1,
                "RST_Flag": 0,
                "FIN_Flag": 0,
                "PSH_Flag": 1 if random.random() < 0.25 else 0,
                "Label": "BENIGN",
            }
            with self._lock:
                self.packets_captured += flow_record["Total_Packets"]
                self.bytes_captured += flow_record["Total_Bytes"]
                self._current_window_flows.append(flow_record)

    def _run_window_evaluator(self):
        """Evaluate accumulated flows every window_seconds and compute forecasts."""
        while not self._stop_requested:
            time.sleep(self.window_seconds)
            if self._stop_requested:
                break
            self._evaluate_current_window()

    def _evaluate_current_window(self):
        """Extract features, run World Model forward pass, and publish frame."""
        with self._lock:
            flows = list(self._current_window_flows)
            self._current_window_flows = []
            window_start = self._current_window_start
            self._current_window_start = datetime.datetime.now()

        # Extract 33-dimensional feature vector
        state_vector = self.pipeline.extract_window_features(flows, window_start)
        state_vector["window_timestamp"] = window_start.strftime("%Y-%m-%d %H:%M:%S")

        with self._lock:
            self.history_sequence.append(state_vector)
            sequence_list = list(self.history_sequence)

        # Run World Model prediction
        prediction = self.world_model.predict_step(sequence_list)
        attack_prob = prediction.get("attack_probability", 0.0)
        current_stage = prediction.get("predicted_stage", "BENIGN")

        # Multi-step autoregressive rollout (next 5 steps = 50 seconds ahead)
        rollout_steps = self.world_model.autoregressive_rollout(sequence_list, horizon_steps=5)

        # Explainability attributions
        attributions = self.explainability_engine.compute_local_attributions(state_vector)

        # Threat scoring & Alert checking
        lead_time = max(0.0, round(float(len(rollout_steps) * self.window_seconds), 1))
        alert = None
        if attack_prob >= 0.50:
            alert = self.alert_engine.process_state(
                timestamp_str=state_vector["window_timestamp"],
                source_ip=flows[0].get("Src_IP", "192.168.1.100") if flows else "192.168.1.100",
                destination_ip=flows[0].get("Dst_IP", "10.0.0.12") if flows else "10.0.0.12",
                attack_probability=attack_prob,
                current_stage=current_stage,
                predicted_next_stage=rollout_steps[0]["predicted_stage"] if rollout_steps else current_stage,
                lead_time_seconds=lead_time,
                features=attributions,
                mitre_candidates=[],
            )

        frame = {
            "type": "LIVE_TELEMETRY_FRAME",
            "timestamp": state_vector["window_timestamp"],
            "window_duration_seconds": self.window_seconds,
            "packets_in_window": sum(int(f.get("Total_Packets", 1)) for f in flows),
            "bytes_in_window": sum(int(f.get("Total_Bytes", 0)) for f in flows),
            "state_vector": state_vector,
            "inference": {
                "attack_probability": attack_prob,
                "predicted_stage": current_stage,
                "stage_probabilities": prediction.get("stage_probabilities", {}),
                "confidence": prediction.get("confidence", 0.85),
                "forecasts": rollout_steps,
                "attributions": attributions[:6],
                "early_warning_lead_time_sec": lead_time,
            },
            "sensor_stats": {
                "interface": self.interface or "All Interfaces",
                "total_packets": self.packets_captured,
                "total_bytes": self.bytes_captured,
                "uptime_seconds": round(time.time() - (self.start_time or time.time()), 1),
            },
            "new_alert": alert,
        }

        with self._lock:
            self.latest_frame = frame
            self.recent_windows.append(frame)

        # Asynchronously broadcast to any connected frontend subscribers
        self._broadcast_frame(frame)

    def inject_simulated_attack(self, stage: str = "RECONNAISSANCE", count: int = 150):
        """
        Inject high-fidelity attack packets directly into the live buffer.
        Allows instant demonstration of live attack detection and forecasting during presentations.
        """
        now = datetime.datetime.now()
        attacker_ip = "192.168.1.250"
        target_ip = "10.0.0.15"
        injected = []

        if stage.upper() == "RECONNAISSANCE":
            # Fast SYN Port Scan signature: High port entropy, high SYN count, short IAT
            for i in range(count):
                injected.append({
                    "Timestamp": now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "Src_IP": attacker_ip,
                    "Dst_IP": target_ip,
                    "Src_Port": random.randint(49152, 65535),
                    "Dst_Port": random.randint(1, 1024),
                    "Protocol": "TCP",
                    "Total_Packets": 2,
                    "Total_Bytes": 120,
                    "Mean_IAT_ms": random.uniform(2.0, 15.0),
                    "SYN_Flag": 1,
                    "ACK_Flag": 0,
                    "RST_Flag": 1 if random.random() < 0.3 else 0,
                    "FIN_Flag": 0,
                    "PSH_Flag": 0,
                    "Label": "RECONNAISSANCE",
                })
        elif stage.upper() == "INITIAL_ACCESS":
            # Credential Spray / SSH Brute Force signature: Port 22, PSH+ACK
            for i in range(count):
                injected.append({
                    "Timestamp": now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "Src_IP": attacker_ip,
                    "Dst_IP": target_ip,
                    "Src_Port": random.randint(49152, 65535),
                    "Dst_Port": 22,
                    "Protocol": "TCP",
                    "Total_Packets": 15,
                    "Total_Bytes": 1250,
                    "Mean_IAT_ms": random.uniform(30.0, 90.0),
                    "SYN_Flag": 1,
                    "ACK_Flag": 1,
                    "RST_Flag": 0,
                    "FIN_Flag": 0,
                    "PSH_Flag": 1,
                    "Label": "INITIAL_ACCESS",
                })
        elif stage.upper() == "COMMAND_AND_CONTROL":
            # C2 Beaconing: Constant interval, high entropy payload
            for i in range(count):
                injected.append({
                    "Timestamp": now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "Src_IP": target_ip,
                    "Dst_IP": "198.51.100.77",
                    "Src_Port": random.randint(49152, 65535),
                    "Dst_Port": 443,
                    "Protocol": "TCP",
                    "Total_Packets": 8,
                    "Total_Bytes": 850,
                    "Mean_IAT_ms": random.uniform(250.0, 310.0),
                    "SYN_Flag": 1,
                    "ACK_Flag": 1,
                    "RST_Flag": 0,
                    "FIN_Flag": 0,
                    "PSH_Flag": 1,
                    "Label": "COMMAND_AND_CONTROL",
                })
        else: # EXFILTRATION
            # Large volume burst
            for i in range(count):
                injected.append({
                    "Timestamp": now.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "Src_IP": target_ip,
                    "Dst_IP": "198.51.100.77",
                    "Src_Port": random.randint(49152, 65535),
                    "Dst_Port": 8443,
                    "Protocol": "TCP",
                    "Total_Packets": 80,
                    "Total_Bytes": 115000,
                    "Mean_IAT_ms": random.uniform(5.0, 25.0),
                    "SYN_Flag": 1,
                    "ACK_Flag": 1,
                    "RST_Flag": 0,
                    "FIN_Flag": 0,
                    "PSH_Flag": 1,
                    "Label": "EXFILTRATION",
                })

        with self._lock:
            self._current_window_flows.extend(injected)
            self.packets_captured += sum(f["Total_Packets"] for f in injected)
            self.bytes_captured += sum(f["Total_Bytes"] for f in injected)

        logger.info(f"Injected {len(injected)} simulated attack flows for stage: {stage}")
        # Trigger an immediate window evaluation so the dashboard updates right away
        self._evaluate_current_window()
        return {"status": "injected", "stage": stage, "flows_count": len(injected)}

    def register_subscriber(self, queue: asyncio.Queue):
        """Add an active WebSocket or async event queue."""
        self._subscribers.add(queue)

    def unregister_subscriber(self, queue: asyncio.Queue):
        """Remove a subscriber queue upon disconnect."""
        self._subscribers.discard(queue)

    def _broadcast_frame(self, frame: Dict[str, Any]):
        """Non-blocking dispatch to all active event queues."""
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(frame)
            except Exception:
                pass

    def get_status(self) -> Dict[str, Any]:
        """Return current status of the live sniffer sensor."""
        uptime = 0.0
        if self.start_time:
            uptime = round(time.time() - self.start_time, 1)

        with self._lock:
            active_flows_in_window = len(self._current_window_flows)

        return {
            "is_running": self.is_running,
            "interface": self.interface or "All Active Adapters",
            "packets_captured": self.packets_captured,
            "bytes_captured": self.bytes_captured,
            "active_flows_in_window": active_flows_in_window,
            "uptime_seconds": uptime,
            "window_duration_seconds": self.window_seconds,
            "has_latest_frame": self.latest_frame is not None,
            "scapy_available": SCAPY_AVAILABLE,
        }
