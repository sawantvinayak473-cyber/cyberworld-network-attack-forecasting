#!/usr/bin/env python3
"""
CyberWorld — Active Defense & Proactive SOAR Mitigation Engine
Closed-loop automated threat neutralization with:
- OS-level Host Firewall Rules (Windows netsh / Linux iptables)
- 1-Click Human Rollback & Auto-Expiry Guardrails
- Critical Infrastructure Whitelist Protection (Gateway, Localhost, DNS)
- Autonomous Predictive Containment Policy Engine
"""

import datetime
import ipaddress
import logging
import os
import platform
import subprocess
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

logger = logging.getLogger("cyberworld_active_defense")

# Critical Infrastructure IPs that must NEVER be quarantined
SAFETY_WHITELIST = {
    "127.0.0.1",
    "::1",
    "localhost",
    "0.0.0.0",
    "255.255.255.255",
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "192.168.1.1",
    "10.0.0.1",
    "172.16.0.1",
}


class ActiveDefenseEngine:
    """
    Manages active defensive containment playbooks, OS firewall orchestration,
    safe sandbox execution, and automated safety rollback timers.
    """

    def __init__(self, db: Optional[Any] = None, default_expiry_minutes: int = 30):
        self.db = db
        self.default_expiry_minutes = default_expiry_minutes
        self.os_type = platform.system()  # 'Windows' or 'Linux' / 'Darwin'

        # In-memory containment registry
        self.active_mitigations: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

        # SOAR Autonomous Defense Policy
        # Modes: 'MANUAL_APPROVAL' (Analyst 1-click) | 'AUTONOMOUS_PREDICTIVE' (Self-executing on Critical risk)
        self.policy_mode = "MANUAL_APPROVAL"
        self.auto_contain_threshold = 0.85

        # Background worker for automatic safety rollbacks
        self._stop_worker = False
        self._worker_thread = threading.Thread(
            target=self._expiry_worker_loop,
            name="CyberWorld-SOAR-ExpiryWorker",
            daemon=True,
        )
        self._worker_thread.start()

        logger.info(f"Active Defense Engine initialized (OS: {self.os_type}, Policy: {self.policy_mode})")

    def is_ip_whitelisted(self, ip_str: str) -> bool:
        """Check whether an IP address belongs to the safety whitelist."""
        clean_ip = ip_str.strip()
        if clean_ip in SAFETY_WHITELIST:
            return True
        try:
            parsed = ipaddress.ip_address(clean_ip)
            if parsed.is_loopback or parsed.is_multicast or parsed.is_unspecified:
                return True
        except ValueError:
            pass
        return False

    def build_firewall_commands(self, target_ip: str, action_type: str = "DROP_INGRESS") -> Dict[str, str]:
        """Formulate platform-specific mitigation and corresponding rollback commands."""
        rule_name = f"CyberWorld_Block_{target_ip.replace('.', '_')}"

        if self.os_type == "Windows":
            if action_type == "DROP_EGRESS":
                apply_cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block remoteip={target_ip}'
                rollback_cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
            else:
                apply_cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={target_ip}'
                rollback_cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'
        else:
            # Linux / Container standard iptables
            if action_type == "DROP_EGRESS":
                apply_cmd = f"iptables -I OUTPUT -d {target_ip} -j DROP"
                rollback_cmd = f"iptables -D OUTPUT -d {target_ip} -j DROP"
            else:
                apply_cmd = f"iptables -I INPUT -s {target_ip} -j DROP"
                rollback_cmd = f"iptables -D INPUT -s {target_ip} -j DROP"

        return {
            "apply_command": apply_cmd,
            "rollback_command": rollback_cmd,
            "rule_name": rule_name,
        }

    def apply_containment(
        self,
        target_ip: str,
        target_stage: str = "INITIAL_ACCESS",
        action_type: str = "DROP_INGRESS",
        execution_mode: str = "LIVE",
        expiry_minutes: Optional[int] = None,
        analyst: str = "SOC-Analyst",
        alert_id: Optional[str] = None,
        notes: str = "",
    ) -> Dict[str, Any]:
        """
        Apply immediate network containment with automated safety rollback guardrails.
        """
        if self.is_ip_whitelisted(target_ip):
            raise ValueError(
                f"Safety Guardrail Rejection: IP {target_ip} is protected on the Infrastructure Whitelist. Containment aborted."
            )

        expiry_mins = expiry_minutes if expiry_minutes is not None else self.default_expiry_minutes
        now = datetime.datetime.now()
        expires_at = (now + datetime.timedelta(minutes=expiry_mins)).strftime("%Y-%m-%d %H:%M:%S") if expiry_mins > 0 else None

        commands = self.build_firewall_commands(target_ip, action_type)
        action_id = f"MIT-{uuid.uuid4().hex[:8].upper()}"

        effective_mode = execution_mode
        exec_output = "Simulated defensive rule recorded."

        if execution_mode.upper() == "LIVE":
            try:
                # Attempt host firewall execution
                res = subprocess.run(
                    commands["apply_command"],
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if res.returncode == 0:
                    exec_output = f"OS Firewall rule successfully installed. ({res.stdout.strip()})"
                else:
                    # Non-admin or container fallback: keep system secure and report sandbox status
                    effective_mode = "SIMULATED_SAFE"
                    exec_output = f"Simulated Sandbox Rule (Host requires Admin privileges: {res.stderr.strip()})"
            except Exception as e:
                effective_mode = "SIMULATED_SAFE"
                exec_output = f"Simulated Sandbox Rule ({e})"

        record = {
            "action_id": action_id,
            "target_ip": target_ip,
            "target_stage": target_stage,
            "action_type": action_type,
            "command_executed": commands["apply_command"],
            "rollback_command": commands["rollback_command"],
            "status": "ACTIVE",
            "applied_at": now.strftime("%Y-%m-%d %H:%M:%S"),
            "expires_at": expires_at,
            "expiry_minutes": expiry_mins,
            "execution_mode": effective_mode,
            "analyst": analyst,
            "alert_id": alert_id,
            "notes": notes or exec_output,
            "output": exec_output,
        }

        with self._lock:
            self.active_mitigations[action_id] = record

        if self.db:
            try:
                self.db.insert_mitigation(record)
            except Exception as e:
                logger.error(f"Failed to persist mitigation in database: {e}")

        logger.info(f"Containment applied [{action_id}] Target: {target_ip} ({effective_mode})")
        return record

    def rollback_containment(self, action_id: str, reason: str = "Analyst Manual Rollback") -> Dict[str, Any]:
        """
        Revert an active defensive containment rule and unblock the target.
        """
        with self._lock:
            record = self.active_mitigations.get(action_id)

        if not record and self.db:
            # Query from persistent DB
            all_records = self.db.get_all_mitigations(limit=100)
            for r in all_records:
                if r["action_id"] == action_id:
                    record = r
                    break

        if not record:
            raise KeyError(f"Mitigation action {action_id} not found.")

        rollback_cmd = record.get("rollback_command", "")
        rollback_output = "Rollback executed."

        if record.get("execution_mode") == "LIVE" and rollback_cmd:
            try:
                res = subprocess.run(
                    rollback_cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                rollback_output = f"OS Firewall rule deleted. ({res.stdout.strip()})"
            except Exception as e:
                rollback_output = f"Rollback command notice: {e}"

        updated_notes = f"{record.get('notes', '')} | Rolled back: {reason}"

        with self._lock:
            if action_id in self.active_mitigations:
                self.active_mitigations[action_id]["status"] = "ROLLED_BACK"
                self.active_mitigations[action_id]["notes"] = updated_notes

        if self.db:
            try:
                self.db.update_mitigation_status(action_id, "ROLLED_BACK", updated_notes)
            except Exception as e:
                logger.error(f"Failed to update rollback in database: {e}")

        logger.info(f"Containment rolled back [{action_id}] Target: {record.get('target_ip')}")
        return {
            "action_id": action_id,
            "target_ip": record.get("target_ip"),
            "status": "ROLLED_BACK",
            "rollback_output": rollback_output,
            "reason": reason,
        }

    def _expiry_worker_loop(self):
        """Background thread checking and unblocking expired quarantine rules."""
        while not self._stop_worker:
            time.sleep(5)
            if self._stop_worker:
                break

            now = datetime.datetime.now()
            expired_ids = []

            with self._lock:
                for action_id, action in list(self.active_mitigations.items()):
                    if action.get("status") == "ACTIVE" and action.get("expires_at"):
                        try:
                            exp = datetime.datetime.strptime(action["expires_at"], "%Y-%m-%d %H:%M:%S")
                            if now >= exp:
                                expired_ids.append(action_id)
                        except ValueError:
                            pass

            for aid in expired_ids:
                try:
                    self.rollback_containment(aid, reason="Safety Expiry Timer Elapsed (Auto-Unblock)")
                    with self._lock:
                        if aid in self.active_mitigations:
                            self.active_mitigations[aid]["status"] = "EXPIRED"
                    if self.db:
                        self.db.update_mitigation_status(aid, "EXPIRED", "Quarantine safety timer expired.")
                    logger.info(f"Containment [{aid}] auto-expired safely.")
                except Exception as e:
                    logger.error(f"Error auto-expiring action {aid}: {e}")

    def evaluate_autonomous_policy(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Closed-loop SOAR trigger: If policy is AUTONOMOUS_PREDICTIVE and predicted threat
        meets criteria, execute proactive micro-containment automatically before compromise.
        """
        if self.policy_mode != "AUTONOMOUS_PREDICTIVE":
            return None

        prob = float(alert.get("attack_probability", 0.0))
        predicted_stage = alert.get("predicted_next_stage", "BENIGN")
        src_ip = alert.get("source_ip", "")

        # Target high-risk forward stages (Initial Access, C2, Exfiltration)
        if prob >= self.auto_contain_threshold and predicted_stage in [
            "INITIAL_ACCESS",
            "COMMAND_AND_CONTROL",
            "EXFILTRATION",
        ]:
            if src_ip and not self.is_ip_whitelisted(src_ip):
                logger.warning(
                    f"SOAR Autonomous Action Triggered: Proactively containing {src_ip} forecasting {predicted_stage}"
                )
                return self.apply_containment(
                    target_ip=src_ip,
                    target_stage=predicted_stage,
                    action_type="DROP_INGRESS",
                    execution_mode="LIVE",
                    expiry_minutes=30,
                    analyst="Autonomous-WorldModel-SOAR",
                    alert_id=alert.get("id"),
                    notes=f"Autonomous Proactive Containment: World Model forecasted {predicted_stage} at P={prob:.2f}",
                )
        return None

    def get_active_mitigations_list(self) -> List[Dict[str, Any]]:
        """List all currently active defensive mitigations."""
        with self._lock:
            # Active from memory
            active = [m for m in self.active_mitigations.values() if m["status"] in ("ACTIVE", "SIMULATED")]
        if not active and self.db:
            return self.db.get_active_mitigations()
        return active

    def get_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Audit trail of all mitigation actions."""
        if self.db:
            return self.db.get_all_mitigations(limit=limit)
        with self._lock:
            return list(self.active_mitigations.values())[:limit]
