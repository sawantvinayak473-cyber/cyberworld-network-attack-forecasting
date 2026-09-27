import torch
from torch.utils.data import Dataset, DataLoader
from typing import List, Dict, Any, Tuple
import numpy as np
import joblib
import os
import logging
from sklearn.preprocessing import StandardScaler
from cyberworld.data.cic_ids_loader import load_cic_ids_csv, generate_windowed_vectors, create_sequences, chronological_split

logger = logging.getLogger(__name__)

STAGE_LABELS = ['BENIGN', 'RECONNAISSANCE', 'INITIAL_ACCESS', 'LATERAL_MOVEMENT', 'COMMAND_AND_CONTROL', 'EXFILTRATION']

class CyberWorldSequenceDataset(Dataset):
    def __init__(self, sequences: List[Tuple[np.ndarray, int, str]], stage_to_idx: Dict[str, int]):
        """
        PyTorch Dataset for CyberWorld sequences.
        Args:
            sequences: List of tuples (feature_matrix, binary_label, stage_label)
            stage_to_idx: Mapping from stage string to integer index
        """
        self.sequences = sequences
        self.stage_to_idx = stage_to_idx

    def __len__(self) -> int:
        return len(self.sequences)

    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        feature_matrix, binary_label, stage_label = self.sequences[idx]
        
        # Convert to tensors
        features_tensor = torch.tensor(feature_matrix, dtype=torch.float32)
        binary_target = torch.tensor(binary_label, dtype=torch.float32)
        stage_target = torch.tensor(self.stage_to_idx.get(stage_label, 0), dtype=torch.long)
        
        return features_tensor, binary_target, stage_target

    def get_class_weights(self) -> torch.Tensor:
        """Calculate class weights for handling dataset imbalance in cross-entropy loss."""
        counts = np.zeros(len(STAGE_LABELS), dtype=np.float32)
        for _, _, stage_label in self.sequences:
            idx = self.stage_to_idx.get(stage_label, 0)
            counts[idx] += 1
            
        # Avoid division by zero
        counts = np.maximum(counts, 1.0)
        total = np.sum(counts)
        weights = total / (len(STAGE_LABELS) * counts)
        
        return torch.tensor(weights, dtype=torch.float32)

def collate_fn(batch: List[Tuple[torch.Tensor, torch.Tensor, torch.Tensor]]) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
    """Custom collate function for DataLoader if needed."""
    features = torch.stack([item[0] for item in batch])
    binary_targets = torch.stack([item[1] for item in batch])
    stage_targets = torch.stack([item[2] for item in batch])
    return features, binary_targets, stage_targets


def build_datasets(data_dir: str, seq_len: int = 10, window_sec: int = 10, scaler_path: str = "scaler.pkl") -> Tuple[Dataset, Dataset, Dataset, StandardScaler, Dict[str, int]]:
    """
    End-to-end pipeline to build PyTorch datasets from CIC-IDS2017 data.
    """
    logger.info("Loading CIC-IDS2017 data...")
    flows = load_cic_ids_csv(data_dir)
    
    logger.info("Generating windowed vectors...")
    vectors = generate_windowed_vectors(flows, window_sec=window_sec)
    
    logger.info(f"Creating sequences of length {seq_len}...")
    sequences = create_sequences(vectors, seq_len=seq_len)
    
    logger.info("Splitting dataset chronologically...")
    train_seqs, val_seqs, test_seqs = chronological_split(sequences, train_ratio=0.7, val_ratio=0.15)
    
    logger.info("Fitting scaler on training data only...")
    # Extract training features to fit scaler
    # Shape of train_seqs[i][0] is (seq_len, num_features)
    train_features = []
    for seq in train_seqs:
        train_features.append(seq[0])
        
    if not train_features:
        raise ValueError("No training data available to fit the scaler.")
        
    train_features_flat = np.vstack(train_features)
    
    scaler = StandardScaler()
    scaler.fit(train_features_flat)
    
    # Save scaler
    joblib.dump(scaler, scaler_path)
    logger.info(f"Scaler saved to {scaler_path}")
    
    # Apply scaler to all sequences
    def scale_sequences(seqs):
        scaled_seqs = []
        for feature_matrix, bin_lbl, stage_lbl in seqs:
            scaled_matrix = scaler.transform(feature_matrix)
            scaled_seqs.append((scaled_matrix, bin_lbl, stage_lbl))
        return scaled_seqs
        
    train_seqs = scale_sequences(train_seqs)
    val_seqs = scale_sequences(val_seqs)
    test_seqs = scale_sequences(test_seqs)
    
    # Stage label mapping
    stage_to_idx = {stage: i for i, stage in enumerate(STAGE_LABELS)}
    
    train_dataset = CyberWorldSequenceDataset(train_seqs, stage_to_idx)
    val_dataset = CyberWorldSequenceDataset(val_seqs, stage_to_idx)
    test_dataset = CyberWorldSequenceDataset(test_seqs, stage_to_idx)
    
    logger.info(f"Built datasets: Train={len(train_dataset)}, Val={len(val_dataset)}, Test={len(test_dataset)}")
    
    return train_dataset, val_dataset, test_dataset, scaler, stage_to_idx
