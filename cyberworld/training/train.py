#!/usr/bin/env python3
import os
import sys
import json
import argparse
import csv
import math
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score

workspace_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, workspace_dir)

from cyberworld.models.world_model import CyberWorldLSTMModel, STAGE_LABELS
from cyberworld.data.feature_engineering.pipeline import NetworkFeaturePipeline, FEATURE_NAMES
from cyberworld.data.generate_sample import generate_chronological_dataset

class CyberWorldDataset(Dataset):
    def __init__(self, vectors, seq_len=10, scaler=None):
        self.seq_len = seq_len
        self.feature_names = FEATURE_NAMES
        self.stage_labels = STAGE_LABELS
        
        self.X_raw = []
        self.Y_attack = []
        self.Y_stage = []
        self.Y_state = []
        
        for i in range(len(vectors) - seq_len):
            window = vectors[i:i+seq_len]
            target = vectors[i+seq_len]
            self.X_raw.append([[v[f] for f in self.feature_names] for v in window])
            self.Y_attack.append(target['is_attack'])
            self.Y_stage.append(self.stage_labels.index(target['ground_truth_stage']))
            self.Y_state.append([target[f] for f in self.feature_names])
            
        self.X_raw = np.array(self.X_raw, dtype=np.float32)
        self.Y_state = np.array(self.Y_state, dtype=np.float32)
        
        if len(self.X_raw) > 0:
            if scaler is None:
                self.scaler = StandardScaler()
                flat_X = self.X_raw.reshape(-1, len(self.feature_names))
                self.scaler.fit(flat_X)
            else:
                self.scaler = scaler
                
            orig_shape = self.X_raw.shape
            self.X = self.scaler.transform(self.X_raw.reshape(-1, len(self.feature_names))).reshape(orig_shape)
            self.Y_state = self.scaler.transform(self.Y_state)
        else:
            self.X = self.X_raw
            self.scaler = scaler
        
    def __len__(self):
        return len(self.X)
        
    def __getitem__(self, idx):
        return (
            torch.tensor(self.X[idx]),
            torch.tensor(self.Y_attack[idx], dtype=torch.float32),
            torch.tensor(self.Y_stage[idx], dtype=torch.long),
            torch.tensor(self.Y_state[idx])
        )

def load_flows(data_path):
    flows = []
    with open(data_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            flows.append(row)
    return flows

def get_class_weights(dataset, num_classes):
    # Support both dataset types
    if hasattr(dataset, 'get_class_weights'):
        return dataset.get_class_weights()
    counts = np.zeros(num_classes)
    for y in dataset.Y_stage:
        counts[y] += 1
    weights = np.ones(num_classes)
    total = len(dataset)
    for i in range(num_classes):
        if counts[i] > 0:
            weights[i] = total / (num_classes * counts[i])
    return torch.tensor(weights, dtype=torch.float32)

def train_model(args):
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"[*] Using device: {device}")
    
    # Set seeds
    torch.manual_seed(42)
    np.random.seed(42)

    try:
        from cyberworld.training.dataset import build_datasets
        # build_datasets expects a directory of CIC-IDS2017 CSVs
        train_ds, val_ds, test_ds, _scaler, _labels = build_datasets(args.data_dir, seq_len=args.seq_len)
        train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True, num_workers=0)
        val_loader = DataLoader(val_ds, batch_size=args.batch_size, shuffle=False, num_workers=0)
        test_loader = DataLoader(test_ds, batch_size=args.batch_size, shuffle=False, num_workers=0)
        train_dataset = train_ds
    except Exception as e:
        print(f"[!] CIC-IDS2017/build_datasets not available ({e}). Generating synthetic data...")
        if not os.path.exists(args.data_dir):
            os.makedirs(os.path.dirname(os.path.abspath(args.data_dir)), exist_ok=True)
            generate_chronological_dataset(output_path=args.data_dir, records_per_stage=500)
            
        flows = load_flows(args.data_dir)
        print(f"[*] Loaded {len(flows)} chronological flow records.")
        
        # Use 2-second windows for synthetic data (flows are dense in time)
        pipeline = NetworkFeaturePipeline(window_seconds=2)
        vectors = pipeline.process_flow_sequence(flows)
        print(f"[*] Extracted {len(vectors)} state vectors across timeline.")
        
        n = len(vectors)
        train_end = int(0.70 * n)
        val_end = int(0.85 * n)
        
        train_vectors = vectors[:train_end]
        val_vectors = vectors[train_end:val_end]
        test_vectors = vectors[val_end:]
        
        
        # Ensure each split has enough vectors for at least 1 sequence (seq_len + 1)
        min_vecs = args.seq_len + 1
        if len(train_vectors) < min_vecs:
            raise ValueError(f"Not enough vectors for training ({len(train_vectors)} < {min_vecs}). "
                             "Generate more data or use a smaller window/seq_len.")
        
        train_dataset = CyberWorldDataset(train_vectors, seq_len=args.seq_len)
        
        # If val/test splits are too small, reuse train data for validation
        if len(val_vectors) >= min_vecs:
            val_dataset = CyberWorldDataset(val_vectors, seq_len=args.seq_len, scaler=train_dataset.scaler)
        else:
            print(f"[!] Validation split too small ({len(val_vectors)} vectors). Using train data for validation.")
            val_dataset = train_dataset
            
        if len(test_vectors) >= min_vecs:
            test_dataset = CyberWorldDataset(test_vectors, seq_len=args.seq_len, scaler=train_dataset.scaler)
        else:
            print(f"[!] Test split too small ({len(test_vectors)} vectors). Using train data for testing.")
            test_dataset = train_dataset
        
        train_loader = DataLoader(train_dataset, batch_size=args.batch_size, shuffle=True, num_workers=0)
        val_loader = DataLoader(val_dataset, batch_size=args.batch_size, shuffle=False, num_workers=0)
        test_loader = DataLoader(test_dataset, batch_size=args.batch_size, shuffle=False, num_workers=0)

    model = CyberWorldLSTMModel(
        input_dim=len(FEATURE_NAMES), 
        hidden_dim=args.hidden_dim, 
        num_layers=args.num_layers, 
        dropout=0.3
    ).to(device)

    # Compute class weights for stage classification
    class_weights = get_class_weights(train_dataset, len(STAGE_LABELS)).to(device)

    bce_loss = nn.BCELoss()
    ce_loss = nn.CrossEntropyLoss(weight=class_weights)
    mse_loss = nn.MSELoss()

    optimizer = optim.AdamW(model.parameters(), lr=args.lr)
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode='min', patience=3, factor=0.5)

    best_val_loss = float('inf')
    early_stop_patience = 5
    early_stop_counter = 0

    print("[*] Starting training loop...")
    for epoch in range(1, args.epochs + 1):
        model.train()
        train_loss = 0.0
        
        for batch_X, batch_attack, batch_stage, batch_state in train_loader:
            batch_X = batch_X.to(device)
            batch_attack = batch_attack.to(device).unsqueeze(1)
            batch_stage = batch_stage.to(device)
            batch_state = batch_state.to(device)

            optimizer.zero_grad()
            outputs = model(batch_X)
            
            loss_attack = bce_loss(outputs['attack_probability'], batch_attack)
            loss_stage = ce_loss(outputs['stage_logits'], batch_stage)
            loss_state = mse_loss(outputs['next_state_vector'], batch_state)
            
            loss = loss_attack + loss_stage + 0.1 * loss_state
            loss.backward()
            
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()
            
            train_loss += loss.item() * batch_X.size(0)

        train_loss /= len(train_loader.dataset)

        model.eval()
        val_loss = 0.0
        all_preds = []
        all_targets = []
        
        with torch.no_grad():
            for batch_X, batch_attack, batch_stage, batch_state in val_loader:
                batch_X = batch_X.to(device)
                batch_attack = batch_attack.to(device).unsqueeze(1)
                batch_stage = batch_stage.to(device)
                batch_state = batch_state.to(device)

                outputs = model(batch_X)
                
                loss_attack = bce_loss(outputs['attack_probability'], batch_attack)
                loss_stage = ce_loss(outputs['stage_logits'], batch_stage)
                loss_state = mse_loss(outputs['next_state_vector'], batch_state)
                
                loss = loss_attack + loss_stage + 0.1 * loss_state
                val_loss += loss.item() * batch_X.size(0)
                
                preds = (outputs['attack_probability'].cpu().numpy() > 0.5).astype(int)
                all_preds.extend(preds)
                all_targets.extend(batch_attack.cpu().numpy())

        val_loss /= len(val_loader.dataset)
        scheduler.step(val_loss)
        
        val_f1 = f1_score(all_targets, all_preds, zero_division=0)
        
        print(f"    Epoch {epoch:02d}/{args.epochs:02d} | Train Loss: {train_loss:.4f} | Val Loss: {val_loss:.4f} | Val F1: {val_f1:.3f}")

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            early_stop_counter = 0
            
            # evaluate on test set to get metrics for saving
            test_loss, test_f1, test_prec, test_rec, test_auc = evaluate_on_test(model, test_loader, device, bce_loss, ce_loss, mse_loss)
            
            os.makedirs(os.path.join(args.output_dir, "models"), exist_ok=True)
            ckpt_path = os.path.join(args.output_dir, "models", "cyberworld_model.pt")
            
            torch.save({
                'model_state_dict': model.state_dict(),
                'model_config': {'input_dim': len(FEATURE_NAMES), 'hidden_dim': args.hidden_dim, 'num_layers': args.num_layers, 'dropout': 0.3},
                'optimizer_state_dict': optimizer.state_dict(),
                'epoch': epoch,
                'train_loss': train_loss,
                'val_loss': val_loss,
                'feature_names': FEATURE_NAMES,
                'stage_labels': STAGE_LABELS,
                'scaler_mean': train_dataset.scaler.mean_.tolist(),
                'scaler_scale': train_dataset.scaler.scale_.tolist(),
                'training_metadata': {'test_f1': test_f1, 'test_loss': test_loss}
            }, ckpt_path)
            
            os.makedirs(os.path.join(args.output_dir, "configs"), exist_ok=True)
            metrics_file = os.path.join(args.output_dir, "configs", "model_config.json")
            
            metrics_dict = {
                "model_name": "CyberWorld-LSTM-v1.2",
                "trained_epochs": epoch,
                "input_features": len(FEATURE_NAMES),
                "f1_score": float(test_f1),
                "precision": float(test_prec),
                "recall": float(test_rec),
                "roc_auc": float(test_auc),
                "test_loss": float(test_loss)
            }
            with open(metrics_file, "w", encoding="utf-8") as f:
                json.dump(metrics_dict, f, indent=2)
                
        else:
            early_stop_counter += 1
            if early_stop_counter >= early_stop_patience:
                print(f"[*] Early stopping triggered at epoch {epoch}")
                break

    print(f"[+] Model checkpoint saved to: {ckpt_path}")
    print(f"[+] Test evaluation metrics saved to: {metrics_file}")
    print(f"[+] Training completed successfully with test F1={test_f1:.3f}.")

def evaluate_on_test(model, test_loader, device, bce, ce, mse):
    model.eval()
    test_loss = 0.0
    all_preds = []
    all_targets = []
    all_probs = []
    
    with torch.no_grad():
        for batch_X, batch_attack, batch_stage, batch_state in test_loader:
            batch_X = batch_X.to(device)
            batch_attack = batch_attack.to(device).unsqueeze(1)
            batch_stage = batch_stage.to(device)
            batch_state = batch_state.to(device)

            outputs = model(batch_X)
            
            loss_attack = bce(outputs['attack_probability'], batch_attack)
            loss_stage = ce(outputs['stage_logits'], batch_stage)
            loss_state = mse(outputs['next_state_vector'], batch_state)
            
            loss = loss_attack + loss_stage + 0.1 * loss_state
            test_loss += loss.item() * batch_X.size(0)
            
            probs = outputs['attack_probability'].cpu().numpy()
            preds = (probs > 0.5).astype(int)
            
            all_preds.extend(preds)
            all_probs.extend(probs)
            all_targets.extend(batch_attack.cpu().numpy())
            
    test_loss /= len(test_loader.dataset)
    if len(all_targets) > 0:
        f1 = f1_score(all_targets, all_preds, zero_division=0)
        prec = precision_score(all_targets, all_preds, zero_division=0)
        rec = recall_score(all_targets, all_preds, zero_division=0)
        try:
            auc = roc_auc_score(all_targets, all_probs)
        except ValueError:
            auc = 0.5 # In case only one class is present in test set
    else:
        f1, prec, rec, auc = 0.0, 0.0, 0.0, 0.0
        
    return test_loss, f1, prec, rec, auc

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train CyberWorld sequence model")
    parser.add_argument("--data_dir", default="artifacts/sample_traffic.csv", help="Input CSV path")
    parser.add_argument("--epochs", type=int, default=25, help="Training epochs")
    parser.add_argument("--batch_size", type=int, default=32, help="Batch size")
    parser.add_argument("--lr", type=float, default=1e-3, help="Learning rate")
    parser.add_argument("--hidden_dim", type=int, default=128, help="LSTM hidden dimension")
    parser.add_argument("--num_layers", type=int, default=2, help="LSTM number of layers")
    parser.add_argument("--seq_len", type=int, default=10, help="Sequence length")
    parser.add_argument("--output_dir", default="artifacts", help="Output directory")
    args = parser.parse_args()
    
    train_model(args)
