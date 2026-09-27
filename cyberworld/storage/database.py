#!/usr/bin/env python3
"""
CyberWorld — SQLite Relational Storage Layer
Provides persistent schemas for flows, state vectors, forecasts, alerts, and investigations.
Uses Python standard library sqlite3 for zero external dependencies.
"""

import os
import sqlite3
import json
from typing import Dict, Any, List, Optional

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS network_flows (
    flow_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    protocol TEXT,
    duration_ms REAL,
    total_packets INTEGER,
    total_bytes INTEGER,
    mean_iat_ms REAL,
    syn_flag INTEGER,
    ack_flag INTEGER,
    rst_flag INTEGER,
    fin_flag INTEGER,
    psh_flag INTEGER,
    label TEXT
);

CREATE TABLE IF NOT EXISTS state_vectors (
    window_id INTEGER PRIMARY KEY AUTOINCREMENT,
    window_start TEXT NOT NULL,
    window_duration_sec INTEGER NOT NULL,
    flow_count INTEGER,
    byte_count INTEGER,
    syn_ack_ratio REAL,
    port_entropy REAL,
    burstiness REAL,
    ground_truth_stage TEXT,
    raw_vector_json TEXT
);

CREATE TABLE IF NOT EXISTS forecasts (
    forecast_id INTEGER PRIMARY KEY AUTOINCREMENT,
    window_id INTEGER,
    timestamp TEXT,
    horizon_step INTEGER,
    horizon_seconds INTEGER,
    predicted_stage TEXT,
    attack_probability REAL,
    confidence REAL,
    FOREIGN KEY(window_id) REFERENCES state_vectors(window_id)
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    source_ip TEXT,
    destination_ip TEXT,
    current_stage TEXT,
    predicted_next_stage TEXT,
    attack_probability REAL,
    early_warning_sec REAL,
    dedup_count INTEGER DEFAULT 1,
    analyst_notes TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS investigations (
    incident_id TEXT PRIMARY KEY,
    alert_id TEXT,
    analyst_notes TEXT,
    actions_taken TEXT,
    updated_at TEXT,
    FOREIGN KEY(alert_id) REFERENCES alerts(alert_id)
);

CREATE TABLE IF NOT EXISTS ioc_cache (
    ip TEXT PRIMARY KEY,
    enrichment_json TEXT NOT NULL,
    cached_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mitigation_actions (
    action_id TEXT PRIMARY KEY,
    target_ip TEXT NOT NULL,
    target_stage TEXT NOT NULL,
    action_type TEXT NOT NULL,
    command_executed TEXT NOT NULL,
    rollback_command TEXT NOT NULL,
    status TEXT NOT NULL,
    applied_at TEXT NOT NULL,
    expires_at TEXT,
    execution_mode TEXT NOT NULL,
    analyst TEXT NOT NULL,
    alert_id TEXT,
    notes TEXT DEFAULT ''
);
"""

class CyberWorldDatabase:
    def __init__(self, db_path: str = "artifacts/cyberworld.db"):
        self.db_path = db_path
        self._shared_conn = None
        if db_path == ":memory:":
            self._shared_conn = sqlite3.connect(":memory:")
            self._shared_conn.row_factory = sqlite3.Row
        else:
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self.init_db()

    def get_connection(self):
        if self._shared_conn is not None:
            return self._shared_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        with self.get_connection() as conn:
            conn.executescript(SCHEMA_SQL)
            conn.commit()

    def insert_alert(self, alert_dict: Dict[str, Any]):
        sql = """
        INSERT OR REPLACE INTO alerts (
            alert_id, timestamp, severity, status, source_ip, destination_ip,
            current_stage, predicted_next_stage, attack_probability, early_warning_sec,
            dedup_count, analyst_notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self.get_connection() as conn:
            conn.execute(sql, (
                alert_dict['id'],
                alert_dict.get('timestamp', ''),
                alert_dict.get('severity', 'ELEVATED'),
                alert_dict.get('status', 'NEW'),
                alert_dict.get('source_ip', ''),
                alert_dict.get('destination_ip', ''),
                alert_dict.get('current_stage', 'BENIGN'),
                alert_dict.get('predicted_next_stage', 'BENIGN'),
                alert_dict.get('attack_probability', 0.0),
                alert_dict.get('early_warning_lead_time_sec', 0.0),
                alert_dict.get('count', 1),
                alert_dict.get('analyst_notes', ''),
            ))
            conn.commit()

    def update_alert_notes(self, alert_id: str, notes: str):
        sql = "UPDATE alerts SET analyst_notes = ? WHERE alert_id = ?"
        with self.get_connection() as conn:
            conn.execute(sql, (notes, alert_id))
            conn.commit()

    def get_all_alerts(self) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM alerts ORDER BY timestamp DESC"
        with self.get_connection() as conn:
            cursor = conn.execute(sql)
            return [dict(row) for row in cursor.fetchall()]

    def insert_mitigation(self, action: Dict[str, Any]):
        sql = """
        INSERT OR REPLACE INTO mitigation_actions (
            action_id, target_ip, target_stage, action_type, command_executed,
            rollback_command, status, applied_at, expires_at, execution_mode,
            analyst, alert_id, notes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        with self.get_connection() as conn:
            conn.execute(sql, (
                action['action_id'],
                action['target_ip'],
                action.get('target_stage', 'UNKNOWN'),
                action.get('action_type', 'FIREWALL_DROP'),
                action['command_executed'],
                action['rollback_command'],
                action.get('status', 'ACTIVE'),
                action['applied_at'],
                action.get('expires_at'),
                action.get('execution_mode', 'SIMULATED'),
                action.get('analyst', 'SOC-Analyst'),
                action.get('alert_id'),
                action.get('notes', ''),
            ))
            conn.commit()

    def update_mitigation_status(self, action_id: str, status: str, notes: str = ''):
        sql = "UPDATE mitigation_actions SET status = ?, notes = ? WHERE action_id = ?"
        with self.get_connection() as conn:
            conn.execute(sql, (status, notes, action_id))
            conn.commit()

    def get_active_mitigations(self) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM mitigation_actions WHERE status IN ('ACTIVE', 'SIMULATED') ORDER BY applied_at DESC"
        with self.get_connection() as conn:
            cursor = conn.execute(sql)
            return [dict(row) for row in cursor.fetchall()]

    def get_all_mitigations(self, limit: int = 50) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM mitigation_actions ORDER BY applied_at DESC LIMIT ?"
        with self.get_connection() as conn:
            cursor = conn.execute(sql, (limit,))
            return [dict(row) for row in cursor.fetchall()]
