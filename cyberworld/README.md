# CyberWorld Backend — Python ML Pipeline & REST API

## Architecture

```
cyberworld/
├── backend/
│   ├── api.py          ← FastAPI REST endpoints + Gemini proxy
│   ├── enrichment.py   ← AbuseIPDB / OTX IOC enrichment
│   └── ingestion.py    ← PCAP file ingestion service
├── configs/
│   └── config.yaml     ← System configuration
├── cybersecurity/
│   ├── alert_engine.py     ← Alert generation + deduplication
│   ├── mitre.py            ← MITRE ATT&CK technique mapping
│   ├── recommendations.py  ← Defensive containment commands
│   └── threat_scoring.py   ← Multi-factor risk scoring
├── data/
│   ├── cic_ids_loader.py       ← CIC-IDS2017 CSV loader + label mapping
│   ├── feature_engineering/
│   │   └── pipeline.py         ← 33-feature window extraction
│   └── generate_sample.py      ← Synthetic telemetry generator
├── models/
│   ├── baseline.py         ← Random Forest baseline (sklearn)
│   ├── explainability.py   ← Permutation importance + optional Captum
│   ├── forecasting.py      ← Autoregressive rollout engine
│   └── world_model.py      ← PyTorch LSTM architecture (33→128→3 heads)
├── storage/
│   └── database.py         ← SQLite persistence layer
├── tests/
│   └── test_suite.py       ← 33 automated tests
├── training/
│   ├── dataset.py          ← PyTorch Dataset + CIC-IDS2017 pipeline
│   ├── evaluate.py         ← Real metric evaluation (P/R/F1/AUC)
│   └── train.py            ← Real PyTorch training loop
└── requirements.txt
```

## Model Architecture

**CyberWorldLSTMModel** — 2-layer LSTM sequence encoder with 3 output heads:

| Component | Specification |
|---|---|
| Input | 33-dimensional state vector S(t) ∈ ℝ³³ |
| Encoder | LSTM(input=33, hidden=128, layers=2, dropout=0.3) |
| Head 1 (Binary) | Linear(128→64→1) + Sigmoid → P(Attack) |
| Head 2 (Stage) | Linear(128→64→6) → Kill-chain stage logits |
| Head 3 (State) | Linear(128→128→33) → Predicted next state S_hat(t+1) |
| Sequence Input | 10 consecutive windows: [S(t-9), ..., S(t)] |

### Kill-Chain Stages

1. `BENIGN` — Normal network activity
2. `RECONNAISSANCE` — Port scanning, network probing
3. `INITIAL_ACCESS` — Brute force, credential stuffing
4. `LATERAL_MOVEMENT` — XSS, SQL injection, infiltration
5. `COMMAND_AND_CONTROL` — DoS, DDoS, beaconing
6. `EXFILTRATION` — Data theft, staged exfiltration

### 33-Feature Schema

The feature pipeline extracts 33 features per 10-second window:

| Category | Features |
|---|---|
| Volume (8) | flow_count, packet_count, byte_count, bytes_per_second, packets_per_second, bytes_per_flow, packets_per_flow, tcp/udp/icmp ratios |
| Packet (4) | mean/std/min/max packet size |
| Timing (5) | mean/std/min/max IAT, temporal_burstiness |
| Flags (8) | syn/ack/rst/fin/psh counts, syn_ack_ratio, rst_ratio |
| Topology (7) | unique src/dst IPs/ports, src/dst IP entropy, dst port entropy |

## Training

```powershell
# Synthetic data (no external dataset needed)
python -m cyberworld.training.train --epochs 25

# CIC-IDS2017 data
python -m cyberworld.training.train --data_dir path/to/CIC-IDS2017/ --epochs 25
```

### Loss Function

Multi-task weighted loss:
```
L = L_binary(BCE) + L_stage(CrossEntropy with class weights) + 0.1 × L_state(MSE)
```

### Optimizer

- AdamW (lr=1e-3)
- ReduceLROnPlateau (patience=3, factor=0.5)
- Gradient clipping (max_norm=1.0)
- Early stopping (patience=5 on validation loss)

## Evaluation

```powershell
python -m cyberworld.training.evaluate \
  --checkpoint artifacts/models/cyberworld_model.pt \
  --data_dir artifacts/sample_traffic.csv
```

All metrics are computed from actual model predictions — none are hardcoded.

## API

```powershell
uvicorn cyberworld.backend.api:app --host 0.0.0.0 --port 8000
```

### Security Features

- **Gemini API key server-side only** — Frontend calls `/api/copilot/ask` backend proxy
- **Optional API key auth** — Set `CYBERWORLD_API_KEY` env var
- **Rate limiting** — Token bucket on `/api/copilot/*` (10 req/min)
- **Upload size limit** — 50MB max for CSV/PCAP ingestion

## Testing

```powershell
python -m cyberworld.tests.test_suite -v
```

33 tests covering: feature pipeline, synthetic data, world model, PyTorch forward/backward pass, checkpoint save/load, threat scoring, alerts, MITRE mapping, database, explainability, security fixes, anti-fabrication checks.
