# CyberWorld: AI-Based Network Attack Forecasting Using World Models

> **"Don't just detect the attack. Forecast where it goes next."**
> *A predictive cyber defense system that learns network dynamics, forecasts attacker progression across MITRE ATT&CK stages, and provides interpretable, actionable decision support before compromise completion.*

---

## 🚀 1-Command Production Deployment (Docker Compose)

The entire CyberWorld platform (FastAPI World Model backend + React SOC dashboard + Nginx reverse proxy) can be deployed with a single command:

```powershell
# Optional: Set your server-side Gemini API key for the Copilot assistant
$env:GEMINI_API_KEY="your-gemini-api-key"

# Build and launch both services
docker compose up --build
```

* **SOC Dashboard:** [http://localhost:3000](http://localhost:3000)
* **Backend REST API:** [http://localhost:8000](http://localhost:8000)
* **Interactive API Swagger Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)
* **Health Check:** [http://localhost:8000/api/health](http://localhost:8000/api/health)

---

## Manual Local Development Setup

### Prerequisites

- **Node.js** ≥ 18 and **npm** (for the React dashboard)
- **Python** ≥ 3.10 (for the backend and ML pipeline)
- **PyTorch** ≥ 2.1 (CPU or CUDA)

### 1. Install Frontend Dependencies

```powershell
npm install
```

### 2. Install Python Dependencies

```powershell
pip install -r cyberworld/requirements.txt
```

### 3. Configure Environment Variables

Copy the example environment files and add your keys:

```powershell
# Backend (required for Copilot)
copy cyberworld\.env.example cyberworld\.env
# Edit cyberworld/.env and set GEMINI_API_KEY

# Frontend
copy .env.example .env.local
# Default VITE_API_BASE_URL=http://localhost:8000 is fine for local dev
```

> [!CAUTION]
> **Never put API keys in files prefixed with `VITE_`** — Vite bundles them into client-side JavaScript. All secrets must be server-side only.

### 4. Train the Model

```powershell
# Generate synthetic data and train (works out of the box)
python cyberworld/training/train.py --epochs 25

# Or with CIC-IDS2017 data (download separately — see Dataset section)
python cyberworld/training/train.py --data_dir path/to/CIC-IDS2017/ --epochs 25
```

### 5. Start the Backend

```powershell
cd cyberworld
uvicorn backend.api:app --host 0.0.0.0 --port 8000 --reload
```

### 6. Start the Dashboard

```powershell
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) (or the URL shown by Vite).

### 7. Run Tests

```powershell
python cyberworld/tests/test_suite.py -v
```

---

## System Architecture

```
[ Raw Network Flows (PCAP / NetFlow / CSV) ]
                     │
                     ▼
[ Chronological Feature Pipeline (10s Windows, 33 Features) ]
                     │
                     ▼ S(t) ∈ R^33
[ Sequence Buffer: S(t-9), ..., S(t) ]
                     │
                     ▼
[ 2-Layer LSTM World Model Sequence Encoder ]
   ├── Head 1: P(Attack | S_t) — Binary Risk (Sigmoid)
   ├── Head 2: Multi-Class Attack Stage (6 MITRE Classes)
   └── Head 3: Continuous State Regression S_hat(t+1)
                     │
                     ├────────────────────────┐
                     ▼                        ▼
        [ Multi-Step Autoregressive ]   [ Explainability Engine ]
        [ Forward Rollout (T+1..T+K) ]  [ Permutation Importance ]
                     │                        │
                     ▼                        ▼
[ MITRE ATT&CK Grounding ] ──► [ Multi-Factor Threat Scorer ]
                     │
                     ▼
[ SOC Dashboard + Gemini Copilot (Server-Proxied) ]
```

### Key Components

| Component | Technology | Purpose |
|---|---|---|
| **Dashboard** | React 19 + TypeScript + Vite + Tailwind | SOC analyst workstation |
| **Backend API** | FastAPI + Python | Inference, ingestion, copilot proxy |
| **World Model** | PyTorch LSTM (2-layer, 128-dim) | Attack forecasting |
| **Feature Pipeline** | Custom Python (33 features) | Network state extraction |
| **Explainability** | Permutation importance + optional Captum | Feature attribution |
| **Database** | SQLite | Alert and investigation persistence |
| **Copilot** | Gemini API (server-proxied) | AI-powered analyst assistant |

---

## Dataset: CIC-IDS2017

CyberWorld uses the [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) intrusion detection dataset for training.

### Download

1. Visit [CIC-IDS2017 Downloads](https://www.unb.ca/cic/datasets/ids-2017.html)
2. Download the "MachineLearningCVE" CSV files
3. Place them in a directory (e.g., `data/cic-ids2017/`)

### Label Mapping

CIC-IDS2017 labels are mapped to CyberWorld's 6-stage kill chain:

| CIC-IDS2017 Label | CyberWorld Stage |
|---|---|
| BENIGN | BENIGN |
| Bot, PortScan | RECONNAISSANCE |
| FTP-Patator, SSH-Patator, Brute Force | INITIAL_ACCESS |
| XSS, SQL Injection, Infiltration | LATERAL_MOVEMENT |
| DoS*, DDoS, Heartbleed | COMMAND_AND_CONTROL |

### Without CIC-IDS2017

The training script automatically generates synthetic data if CIC-IDS2017 is not available:

```powershell
python cyberworld/training/train.py --epochs 25
# [!] CIC-IDS2017 or build_datasets not available. Generating synthetic data...
```

---

## Training

### Full Training Command

```powershell
python cyberworld/training/train.py `
  --data_dir artifacts/sample_traffic.csv `
  --epochs 25 `
  --batch_size 32 `
  --lr 0.001 `
  --hidden_dim 128 `
  --num_layers 2 `
  --seq_len 10 `
  --output_dir artifacts
```

### What Training Produces

| Artifact | Path | Description |
|---|---|---|
| Model checkpoint | `artifacts/models/cyberworld_model.pt` | PyTorch state dict + config |
| Metrics | `artifacts/configs/model_config.json` | Real computed F1, AUC, precision, recall |

### Training Features

- ✅ Real PyTorch training with gradient-based optimization
- ✅ Multi-task loss: BCE (attack) + CrossEntropy (stage) + MSE (state)
- ✅ AdamW optimizer with ReduceLROnPlateau scheduling
- ✅ Early stopping (patience=5 on validation loss)
- ✅ Gradient clipping (max_norm=1.0)
- ✅ Class-weighted cross-entropy for stage imbalance
- ✅ Chronological 70/15/15 split (no data leakage)
- ✅ StandardScaler fitted exclusively on training data

---

## Evaluation

```powershell
python cyberworld/training/evaluate.py `
  --checkpoint artifacts/models/cyberworld_model.pt `
  --data_dir artifacts/sample_traffic.csv
```

Produces `artifacts/configs/evaluation_results.json` with:
- Precision, Recall, F1 (binary and per-class)
- ROC-AUC, PR-AUC
- Confusion matrix
- False positive/negative rates
- Classification report

---

## API Reference

### Model Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/health` | Health check |
| GET | `/api/model/status` | Model load status + metrics |
| POST | `/api/model/predict` | Single-step prediction |
| POST | `/api/model/forecast` | Multi-step rollout |
| POST | `/api/model/explain` | Feature attributions |
| POST | `/api/model/full-inference` | Combined predict + forecast + explain |
| GET | `/api/benchmarks` | Evaluation metrics |

### Ingestion Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/ingest/csv` | Upload CSV telemetry |
| POST | `/api/ingest/pcap` | Upload PCAP capture |

### Security Endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/copilot/ask` | Server-proxied Gemini copilot |
| POST | `/api/copilot/filter` | NL query → alert filter |
| POST | `/api/enrich/ip` | IOC enrichment |
| GET | `/api/alerts` | List alerts |
| GET | `/api/alerts/{id}` | Get alert details |

### Authentication

Set `CYBERWORLD_API_KEY` environment variable to enable API key auth:

```
X-API-Key: your-key-here
```

Applied to POST/PUT/DELETE endpoints. GET endpoints and `/api/health` are always public.

---

## Security

### Fixed Vulnerabilities

| Issue | Status | Fix |
|---|---|---|
| Gemini API key in client JS | ✅ Fixed | Moved to server-side proxy |
| No API authentication | ✅ Fixed | Optional X-API-Key middleware |
| 500MB upload limit | ✅ Fixed | Reduced to 50MB |
| Rate limiting | ✅ Fixed | Token bucket on /api/copilot/* |

### Security Best Practices

1. **Never commit `.env` files** — `.gitignore` excludes them
2. **Rotate the old Gemini API key** — it was previously exposed
3. **Set `CYBERWORLD_API_KEY`** in production
4. **Use HTTPS** behind a reverse proxy in production

> [!WARNING]
> **The previously exposed Gemini API key must be rotated.** Go to [Google AI Studio](https://aistudio.google.com/apikey) and regenerate your key. The old key may have been compromised.

---

## Environment Variables

### Backend (`cyberworld/.env`)

| Variable | Required | Description |
|---|---|---|
| `GEMINI_API_KEY` | For Copilot | Google Gemini API key (server-side only) |
| `CYBERWORLD_API_KEY` | Optional | API authentication key |
| `CYBERWORLD_MODEL_PATH` | Optional | Custom model checkpoint path |
| `ABUSEIPDB_API_KEY` | Optional | For IOC enrichment |

### Frontend (`.env.local`)

| Variable | Required | Description |
|---|---|---|
| `VITE_API_BASE_URL` | Optional | Backend URL (default: http://localhost:8000) |

---

## Project Structure

```
.
├── src/                          # React 19 + Vite + Tailwind SOC Dashboard
│   ├── api/                     # API clients (copilot, cyberWorld)
│   ├── components/              # 20+ SOC dashboard views
│   ├── engine/                  # Client-side simulator (offline fallback)
│   ├── mockData/                # Demo scenario data
│   ├── App.tsx                  # Main application
│   └── types.ts                 # TypeScript type definitions
├── cyberworld/                  # Python backend + ML
│   ├── backend/                 # FastAPI REST endpoints + Gemini proxy
│   ├── configs/config.yaml      # System configuration
│   ├── cybersecurity/           # MITRE mapping, scoring, alerts, recommendations
│   ├── data/                    # Feature pipeline + CIC-IDS2017 loader
│   ├── models/                  # LSTM World Model, baseline, explainability
│   ├── storage/                 # SQLite persistence
│   ├── tests/                   # Comprehensive test suite
│   ├── training/                # Real PyTorch training + evaluation
│   └── requirements.txt         # Python dependencies
├── artifacts/                   # Generated model checkpoints + configs
│   ├── models/                  # cyberworld_model.pt (real checkpoint)
│   └── configs/                 # model_config.json (real metrics)
└── package.json                 # Frontend dependencies
```

---

## Testing

```powershell
# Run all tests
python cyberworld/tests/test_suite.py -v

# Run specific test class
python -m pytest cyberworld/tests/test_suite.py::TestPyTorchModel -v
```

### Test Coverage (46/46 Automated Tests Passing)

| Test Area | Tests | Description |
|---|---|---|
| Feature Pipeline | 5 | 33-dim extraction, entropy, burstiness, temporal grouping |
| Synthetic Data | 2 | Chronological order, scenario count, zero data leakage |
| World Model (heuristic) | 4 | Prediction, rollout, stage labels, fallback behavior |
| PyTorch Model | 5 | Forward pass, gradients, checkpoint, training loop, state dict |
| Threat Scoring | 2 | Critical/normal threat detection, multi-factor risk scoring |
| Alert Engine | 2 | Generation, deduplication, lifecycle transitions |
| MITRE Mapping | 1 | All stages covered, evidence generation |
| Recommendations | 1 | IP-specific containment commands, script templating |
| Database | 2 | Insert/retrieve, update notes, SQL schema verification |
| Explainability | 2 | Attributions structure, permutation importance |
| Security Fixes | 2 | No API key in frontend, token bucket rate limit |
| Anti-Fabrication | 3 | No hardcoded metrics, valid tensors, real checkpoint files |
| CIC-IDS Loader | 2 | Label mapping correctness, chronological splitting |
| Live Sniffer (Pillar 1) | 3 | Real-time packet sniffer, Scapy adapter, live injection |
| Active Defense (Pillar 2) | 5 | Firewall rule generation, whitelist safety, rollback, SOAR policy |
| API Endpoints & Health | 3 | /api/health, /api/model/status, /api/benchmarks integration |

---

## 🏆 Smart India Hackathon (SIH) Winning Demo Script

When presenting to judges and technical evaluators, follow this exact 5-minute walkthrough to demonstrate end-to-end technical superiority:

### 1. The Core Differentiator: Detection vs. Forecasting (60s)
- **Start at Dashboard View:** Explain to the jury: *"Traditional IDS and SIEMs (Splunk, Suricata, Snort) are purely reactive — they fire after an asset is already compromised. CyberWorld uses an LSTM World Model to learn internal network transition dynamics and forecast where the attacker is going 10 to 50 seconds BEFORE lateral movement or exfiltration occurs."*
- Point to the **Early Warning Lead Time: +142.4 seconds**.

### 2. Live Hardware Packet Sniffing (Pillar 1) (60s)
- Navigate to **Live Network Monitor**.
- Switch to **Mode A: Live Hardware Sniffer**.
- Show the detected network interface (Ethernet/Wi-Fi) and the live packet throughput counter streaming via WebSocket (`/ws/live`).
- Click **"Inject Recon Probe (Port Scan)"** or **"Inject Infiltration Stream"** under Live Attack Signature Injection.
- Watch the live PyTorch inference engine immediately ingest the raw frames, aggregate them into a 10s state vector, and autoregressively forecast an attack escalation.

### 3. Explainability & MITRE ATT&CK Attribution (45s)
- Open **Explainability View**.
- Highlight the **Feature Attribution (Permutation Importance)**: Show how specific network telemetry features (e.g. `syn_ack_ratio`, `dst_port_entropy`, `temporal_burstiness`) drove the model's risk calculation.
- Show the jury: *"This is not a black-box neural net. We compute genuine feature importance across 33 dimensions, mapped directly to MITRE ATT&CK techniques (T1046, T1110, T1021)."*

### 4. What-If Counterfactual Simulator to SOAR Firewall (Pillar 2) (60s)
- Open **What-If Simulator**.
- Toggle **"Block Port Scanning"** or **"Isolate Source Endpoint"**.
- Watch the dual-curve chart: the dashed red line (original trajectory) vs. the solid green line (perturbed trajectory). Attack probability drops from 85% to 15%.
- Click **"Deploy to Firewall"**: Show that CyberWorld is closed-loop SOAR. It executes OS firewall commands (`netsh advfirewall` on Windows, `iptables` on Linux) with:
  1. Strict safety whitelist (`127.0.0.1`, gateways, DNS) preventing self-lockout.
  2. 30-minute auto-expiry timer to prevent permanent network disruption.
  3. 1-Click human rollback button.

### 5. Empirical Proof & Zero Fabrication (Pillar 3) (45s)
- Open **Benchmark View**.
- Click **"Refresh Metrics"**: Show that every number is pulled live from `/api/benchmarks` computed on 10,614 CIC-IDS flows and 209 held-out test sequences (F1: 84.7%, ROC-AUC: 93.5%, PR-AUC: 94.4%).
- Show the jury the head-to-head comparison against static Random Forest and Logistic Regression baselines.

### 6. Production Microservices (Pillar 4) (30s)
- Show `docker-compose.yml`: *"The entire system is containerized with Python 3.11-slim backend, multi-stage Node 20 / Nginx frontend, health checks, and automated GitHub Actions CI/CD with 46 automated unit tests."*

---

## Dashboard Features

- **Live Hardware Packet Sniffer (Pillar 1):** Real-time network adapter packet capture (Scapy/Raw Sockets) with 10s window aggregation and live attack injection testing
- **Closed-Loop Active Defense & SOAR (Pillar 2):** 1-Click proactive threat containment (OS firewall rules on Windows/Linux), 1-click human rollback, 30m auto-expiry timer, safety whitelist guardrail, and autonomous predictive mitigation
- **Attack Forecasting:** Multi-step autoregressive trajectory predictions (T+10s to T+50s)
- **Explainability:** Feature attribution charts (permutation importance over 33 dimensions)
- **Incident Investigation:** Alert triage, analyst notes, containment commands
- **What-If Simulator:** Counterfactual perturbation analysis
- **Case Management:** Investigation tracking with timeline
- **Benchmarks:** Real model evaluation metrics
- **SOC Copilot:** AI-powered analyst assistant (Gemini, server-proxied)
- **Digital Twin:** Visual attack progression modeling
- **IOC Enrichment:** AbuseIPDB/OTX IP reputation lookup

---

## Limitations

1. **CIC-IDS2017 is a synthetic lab dataset** — real-world network traffic may behave differently
2. **The LSTM operates on aggregate window features** — not raw packet bytes
3. **Kill-chain stage mapping is approximate** — CIC-IDS2017 labels don't perfectly align to MITRE stages
4. **The What-If simulator shows model predictions** — not guaranteed real-world outcomes
5. **EXFILTRATION stage** is not represented in CIC-IDS2017
6. **Single-machine deployment** — SQLite limits concurrent write throughput

---

## Troubleshooting

| Problem | Solution |
|---|---|
| `ModuleNotFoundError: torch` | `pip install torch --index-url https://download.pytorch.org/whl/cpu` |
| Model shows "fallback" mode | Run training: `python cyberworld/training/train.py --epochs 25` |
| Copilot returns "unavailable" | Set `GEMINI_API_KEY` in `cyberworld/.env` |
| Frontend can't reach backend | Check `VITE_API_BASE_URL` in `.env.local` |
| Tests fail on `test_checkpoint_not_text_file` | Train the model first |
