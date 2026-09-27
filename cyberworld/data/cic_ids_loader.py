#!/usr/bin/env python3
"""
CyberWorld — CIC-IDS2017 Data Loader
Loads, cleans, and maps CIC-IDS2017 CSV data to CyberWorld's feature schema.
Supports single file or entire directory of CSVs.
"""

import os
import glob
import logging
import datetime
import numpy as np
from collections import Counter
from typing import List, Dict, Tuple, Any, Optional

logger = logging.getLogger(__name__)

# CIC-IDS2017 label -> CyberWorld kill-chain stage mapping
LABEL_TO_STAGE = {
    'BENIGN': 'BENIGN',
    'Bot': 'RECONNAISSANCE',
    'PortScan': 'RECONNAISSANCE',
    'FTP-Patator': 'INITIAL_ACCESS',
    'SSH-Patator': 'INITIAL_ACCESS',
    'Web Attack \u2013 Brute Force': 'INITIAL_ACCESS',
    'Web Attack Brute Force': 'INITIAL_ACCESS',
    'Web Attack \u2013 XSS': 'LATERAL_MOVEMENT',
    'Web Attack XSS': 'LATERAL_MOVEMENT',
    'Web Attack \u2013 Sql Injection': 'LATERAL_MOVEMENT',
    'Web Attack Sql Injection': 'LATERAL_MOVEMENT',
    'Infiltration': 'LATERAL_MOVEMENT',
    'DoS slowloris': 'COMMAND_AND_CONTROL',
    'DoS Slowhttptest': 'COMMAND_AND_CONTROL',
    'DoS Hulk': 'COMMAND_AND_CONTROL',
    'DoS GoldenEye': 'COMMAND_AND_CONTROL',
    'DDoS': 'COMMAND_AND_CONTROL',
    'Heartbleed': 'COMMAND_AND_CONTROL',
}


def map_label(label: str) -> str:
    """Map a CIC-IDS2017 label string to a CyberWorld kill-chain stage."""
    if not isinstance(label, str):
        return 'BENIGN'
    label = label.strip()
    if label in LABEL_TO_STAGE:
        return LABEL_TO_STAGE[label]
    # Fuzzy matching fallback
    label_upper = label.upper()
    if 'BENIGN' in label_upper:
        return 'BENIGN'
    if 'PORTSCAN' in label_upper or 'BOT' in label_upper:
        return 'RECONNAISSANCE'
    if 'PATATOR' in label_upper or 'BRUTE' in label_upper:
        return 'INITIAL_ACCESS'
    if 'XSS' in label_upper or 'SQL' in label_upper or 'INFILTR' in label_upper:
        return 'LATERAL_MOVEMENT'
    if 'DOS' in label_upper or 'DDOS' in label_upper or 'HEARTBLEED' in label_upper:
        return 'COMMAND_AND_CONTROL'
    return 'BENIGN'


def _map_protocol(proto_val) -> str:
    """Map numeric protocol codes to string names."""
    try:
        p = int(float(proto_val))
    except (ValueError, TypeError):
        return 'TCP'
    if p == 6:
        return 'TCP'
    if p == 17:
        return 'UDP'
    if p == 1:
        return 'ICMP'
    return 'OTHER'


def _safe_float(val, default: float = 0.0) -> float:
    """Safely convert a value to float, handling inf/nan/strings."""
    try:
        v = float(val)
        if not np.isfinite(v):
            return default
        return max(0.0, v)
    except (ValueError, TypeError):
        return default


def _safe_int(val, default: int = 0) -> int:
    """Safely convert a value to int."""
    try:
        v = float(val)
        if not np.isfinite(v):
            return default
        return max(0, int(v))
    except (ValueError, TypeError):
        return default


def _get_col(row: dict, *candidates, default=None):
    """Try multiple column names (CIC-IDS2017 has inconsistent spacing)."""
    for c in candidates:
        if c in row:
            return row[c]
    return default


def load_cic_ids_csv(csv_path_or_dir: str) -> List[Dict[str, Any]]:
    """
    Load CIC-IDS2017 CSV files, clean data, and map to the flow dict format
    expected by NetworkFeaturePipeline.extract_window_features().

    Returns a list of flow dicts sorted by timestamp.
    """
    try:
        import pandas as pd
    except ImportError:
        raise ImportError("pandas is required for CIC-IDS2017 loading: pip install pandas")

    if os.path.isdir(csv_path_or_dir):
        files = sorted(glob.glob(os.path.join(csv_path_or_dir, "*.csv")))
        if not files:
            raise FileNotFoundError(f"No CSV files found in directory: {csv_path_or_dir}")
    elif os.path.isfile(csv_path_or_dir):
        files = [csv_path_or_dir]
    else:
        raise FileNotFoundError(f"Path not found: {csv_path_or_dir}")

    logger.info(f"Loading {len(files)} CSV file(s)...")

    all_flows: List[Dict[str, Any]] = []

    for filepath in files:
        logger.info(f"  Reading: {os.path.basename(filepath)}")
        try:
            df = pd.read_csv(filepath, encoding='latin1', low_memory=False)
        except Exception as e:
            logger.error(f"  Error reading {filepath}: {e}")
            continue

        # Clean column names — strip whitespace
        df.columns = [col.strip() for col in df.columns]

        # Replace inf/nan with 0
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(0, inplace=True)

        # Parse timestamps
        ts_col = None
        for candidate in ['Timestamp', 'timestamp', 'Flow ID']:
            if candidate in df.columns:
                ts_col = candidate
                break

        if ts_col and ts_col == 'Timestamp':
            # CIC-IDS2017 uses dd/mm/yyyy hh:mm format
            try:
                df['_parsed_ts'] = pd.to_datetime(
                    df[ts_col],
                    format='%d/%m/%Y %H:%M',
                    errors='coerce'
                )
            except Exception:
                df['_parsed_ts'] = pd.to_datetime(df[ts_col], errors='coerce')

            # Fill unparseable timestamps with forward fill
            df['_parsed_ts'] = df['_parsed_ts'].ffill().bfill()
            if df['_parsed_ts'].isna().all():
                base_ts = datetime.datetime(2017, 7, 3, 9, 0, 0)
                df['_parsed_ts'] = [base_ts + datetime.timedelta(seconds=i) for i in range(len(df))]
        else:
            base_ts = datetime.datetime(2017, 7, 3, 9, 0, 0)
            df['_parsed_ts'] = [base_ts + datetime.timedelta(seconds=i) for i in range(len(df))]

        df = df.sort_values('_parsed_ts').reset_index(drop=True)

        # Convert each row to a flow dict
        for _, row in df.iterrows():
            try:
                fwd_pkts = _safe_float(row.get('Total Fwd Packets', 0))
                bwd_pkts = _safe_float(row.get('Total Backward Packets', 0))
                fwd_bytes = _safe_float(row.get('Total Length of Fwd Packets', 0))
                bwd_bytes = _safe_float(row.get('Total Length of Bwd Packets', 0))

                raw_label = str(row.get('Label', 'BENIGN'))
                stage = map_label(raw_label)

                flow = {
                    'Timestamp': row['_parsed_ts'].strftime('%Y-%m-%d %H:%M:%S.%f'),
                    'Src_IP': str(row.get('Source IP', row.get('Src IP', '0.0.0.0'))),
                    'Src_Port': _safe_int(row.get('Source Port', row.get('Src Port', 0))),
                    'Dst_IP': str(row.get('Destination IP', row.get('Dst IP', '0.0.0.0'))),
                    'Dst_Port': _safe_int(row.get('Destination Port', row.get('Dst Port', 0))),
                    'Protocol': _map_protocol(row.get('Protocol', 6)),
                    'Total_Packets': int(fwd_pkts + bwd_pkts),
                    'Total_Bytes': int(fwd_bytes + bwd_bytes),
                    'Mean_IAT_ms': _safe_float(row.get('Flow IAT Mean', 0)),
                    'SYN_Flag': _safe_int(row.get('SYN Flag Count', 0)),
                    'ACK_Flag': _safe_int(row.get('ACK Flag Count', 0)),
                    'RST_Flag': _safe_int(row.get('RST Flag Count', 0)),
                    'FIN_Flag': _safe_int(row.get('FIN Flag Count', 0)),
                    'PSH_Flag': _safe_int(row.get('PSH Flag Count', 0)),
                    'Label': stage,
                }
                all_flows.append(flow)
            except Exception:
                continue

        logger.info(f"  Parsed {len(df)} rows from {os.path.basename(filepath)}")

    logger.info(f"Total flows loaded: {len(all_flows)}")

    # Print class distribution
    if all_flows:
        labels = [f['Label'] for f in all_flows]
        dist = Counter(labels)
        logger.info("Class Distribution:")
        for stage, count in sorted(dist.items(), key=lambda x: -x[1]):
            pct = count / len(labels) * 100
            logger.info(f"  {stage}: {count:,} ({pct:.2f}%)")

    return all_flows


def generate_windowed_vectors(
    flows: List[Dict[str, Any]],
    window_sec: int = 10,
) -> List[Dict[str, Any]]:
    """
    Use the existing NetworkFeaturePipeline to group flows into
    temporal windows and generate 33-dimensional feature vectors.
    """
    from cyberworld.data.feature_engineering.pipeline import NetworkFeaturePipeline
    pipeline = NetworkFeaturePipeline(window_seconds=window_sec)
    return pipeline.process_flow_sequence(flows)


def create_sequences(
    vectors: List[Dict[str, Any]],
    seq_len: int = 10,
) -> List[Dict[str, Any]]:
    """
    Create overlapping sequences from windowed vectors.
    Each sequence has seq_len input windows and uses the NEXT window as the target.

    Returns list of dicts: {
        'input_vectors': List[Dict],  # seq_len windows
        'target_vector': Dict,        # next window (prediction target)
    }
    """
    sequences = []
    for i in range(len(vectors) - seq_len):
        input_vecs = vectors[i:i + seq_len]
        target_vec = vectors[i + seq_len]
        sequences.append({
            'input_vectors': input_vecs,
            'target_vector': target_vec,
        })
    return sequences


def chronological_split(
    data: list,
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
) -> Tuple[list, list, list]:
    """
    Split data chronologically (no shuffling) into train/val/test sets.
    The test set is (1 - train_ratio - val_ratio) of the data.
    """
    n = len(data)
    train_end = int(n * train_ratio)
    val_end = int(n * (train_ratio + val_ratio))
    return data[:train_end], data[train_end:val_end], data[val_end:]


def print_dataset_summary(
    train: list,
    val: list,
    test: list,
    label_key: str = 'ground_truth_stage',
) -> None:
    """Print summary statistics for a chronological data split."""
    for name, split in [('Train', train), ('Val', val), ('Test', test)]:
        labels = [v.get(label_key, 'UNKNOWN') for v in split]
        dist = Counter(labels)
        attack_pct = (1 - dist.get('BENIGN', 0) / max(1, len(labels))) * 100
        logger.info(f"  {name}: {len(split)} windows | Attack: {attack_pct:.1f}% | {dict(dist)}")
