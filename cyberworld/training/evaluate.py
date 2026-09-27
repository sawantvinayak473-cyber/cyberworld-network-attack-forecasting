#!/usr/bin/env python3
import os
import sys
import json
import argparse
import csv
import torch
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, precision_recall_fscore_support, roc_auc_score, average_precision_score
from torch.utils.data import DataLoader

workspace_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, workspace_dir)

from cyberworld.models.world_model import CyberWorldLSTMModel, STAGE_LABELS
from cyberworld.data.feature_engineering.pipeline import NetworkFeaturePipeline, FEATURE_NAMES
from cyberworld.training.train import CyberWorldDataset

def evaluate_model(args):
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    print(f"[*] Evaluation Device: {device}")
    print(f"[*] Loading checkpoint: {args.checkpoint}")
    
    if not os.path.exists(args.checkpoint):
        print(f"[!] Checkpoint not found: {args.checkpoint}")
        return
        
    checkpoint = torch.load(args.checkpoint, map_location=device, weights_only=False)
    config = checkpoint.get('model_config', {})
    
    input_dim = config.get('input_dim', len(FEATURE_NAMES))
    hidden_dim = config.get('hidden_dim', 128)
    num_layers = config.get('num_layers', 2)
    dropout = config.get('dropout', 0.3)
    
    model = CyberWorldLSTMModel(
        input_dim=input_dim,
        hidden_dim=hidden_dim,
        num_layers=num_layers,
        dropout=dropout
    ).to(device)
    
    model.load_state_dict(checkpoint['model_state_dict'])
    model.eval()
    
    print(f"[*] Loading data from: {args.data_dir}")
    if not os.path.exists(args.data_dir):
        print(f"[!] Data not found: {args.data_dir}")
        return
        
    flows = []
    with open(args.data_dir, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            flows.append(row)
            
    pipeline = NetworkFeaturePipeline(window_seconds=10)
    vectors = pipeline.process_flow_sequence(flows)
    
    from sklearn.preprocessing import StandardScaler
    scaler = StandardScaler()
    scaler.mean_ = np.array(checkpoint['scaler_mean'])
    scaler.scale_ = np.array(checkpoint['scaler_scale'])
    scaler.var_ = scaler.scale_ ** 2
    
    test_dataset = CyberWorldDataset(vectors, seq_len=10, scaler=scaler)
    test_loader = DataLoader(test_dataset, batch_size=32, shuffle=False)
    
    all_attack_probs = []
    all_attack_preds = []
    all_attack_targets = []
    
    all_stage_preds = []
    all_stage_targets = []
    
    print("[*] Running inference...")
    with torch.no_grad():
        for batch_X, batch_attack, batch_stage, batch_state in test_loader:
            batch_X = batch_X.to(device)
            outputs = model(batch_X)
            
            probs = outputs['attack_probability'].cpu().numpy().flatten()
            preds = (probs > 0.5).astype(int)
            
            stage_logits = outputs['stage_logits'].cpu().numpy()
            stage_preds = np.argmax(stage_logits, axis=1)
            
            all_attack_probs.extend(probs)
            all_attack_preds.extend(preds)
            all_attack_targets.extend(batch_attack.numpy())
            
            all_stage_preds.extend(stage_preds)
            all_stage_targets.extend(batch_stage.numpy())
            
    all_attack_targets = np.array(all_attack_targets)
    all_attack_preds = np.array(all_attack_preds)
    all_attack_probs = np.array(all_attack_probs)
    
    all_stage_targets = np.array(all_stage_targets)
    all_stage_preds = np.array(all_stage_preds)
    
    if len(all_attack_targets) == 0:
        print("[!] No data available in test set for evaluation.")
        return
        
    precision, recall, f1, _ = precision_recall_fscore_support(all_attack_targets, all_attack_preds, average='binary', zero_division=0)
    
    try:
        roc_auc = roc_auc_score(all_attack_targets, all_attack_probs)
    except ValueError:
        roc_auc = 0.5
        
    try:
        pr_auc = average_precision_score(all_attack_targets, all_attack_probs)
    except ValueError:
        pr_auc = 0.0
        
    cm = confusion_matrix(all_attack_targets, all_attack_preds)
    if cm.shape == (2,2):
        tn, fp, fn, tp = cm.ravel()
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
    else:
        fpr, fnr = 0.0, 0.0
        
    present_stages = sorted(list(set(all_stage_targets)))
    target_names = [STAGE_LABELS[i] for i in present_stages]
    
    cls_report = classification_report(all_stage_targets, all_stage_preds, target_names=target_names, zero_division=0, output_dict=True)
    
    results = {
        "binary_metrics": {
            "precision": float(precision),
            "recall": float(recall),
            "f1_score": float(f1),
            "roc_auc": float(roc_auc),
            "pr_auc": float(pr_auc),
            "false_positive_rate": float(fpr),
            "false_negative_rate": float(fnr)
        },
        "stage_metrics": cls_report
    }
    
    out_dir = os.path.join(workspace_dir, "artifacts", "configs")
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "evaluation_results.json")
    
    with open(out_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
        
    print(f"\n[+] Results saved to: {out_file}")
    print("\n--- Binary Classification Report ---")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 Score:  {f1:.4f}")
    print(f"ROC-AUC:   {roc_auc:.4f}")
    print(f"PR-AUC:    {pr_auc:.4f}")
    print(f"FPR:       {fpr:.4f}")
    print(f"FNR:       {fnr:.4f}")
    
    print("\n--- Stage Classification Report ---")
    print(classification_report(all_stage_targets, all_stage_preds, target_names=target_names, zero_division=0))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate CyberWorld sequence model")
    parser.add_argument("--checkpoint", required=True, help="Path to model checkpoint")
    parser.add_argument("--data_dir", required=True, help="Path to test data CSV")
    args = parser.parse_args()
    
    evaluate_model(args)
