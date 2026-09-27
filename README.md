# CyberWorld
## AI-Based Network Attack Forecasting Using an LSTM World Model

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/PyTorch-2.1%2B-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white" alt="PyTorch">
  <img src="https://img.shields.io/badge/FastAPI-Backend-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/React-19-61DAFB?style=for-the-badge&logo=react&logoColor=111827" alt="React">
  <img src="https://img.shields.io/badge/TypeScript-5%2B-3178C6?style=for-the-badge&logo=typescript&logoColor=white" alt="TypeScript">
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker">
</p>

> **Don't just detect the attack. Forecast where it goes next.**

CyberWorld is a cybersecurity decision-support platform that models network activity as a time-evolving state, uses a PyTorch LSTM to forecast attack risk and likely attack-stage progression, explains the factors behind a prediction, and connects those predictions to SOC workflows such as alert triage, what-if analysis, IOC enrichment, and controlled response actions.

The platform is designed around a simple operational loop:

**Observe → Model → Forecast → Explain → Investigate → Simulate → Respond**

---

## Table of Contents

- [Why CyberWorld](#why-cyberworld)
- [Core Problem](#core-problem)
- [What CyberWorld Does](#what-cyberworld-does)
- [System Architecture](#system-architecture)
- [Core Components](#core-components)
- [Key Capabilities](#key-capabilities)
- [Machine Learning Pipeline](#machine-learning-pipeline)
- [Model Evaluation](#model-evaluation)
- [Dataset](#dataset)
- [MITRE ATT&CK Grounding](#mitre-attck-grounding)
- [Security Architecture](#security-architecture)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [Training](#training)
- [Evaluation](#evaluation)
- [API Reference](#api-reference)
- [Testing](#testing)
- [SIH Demo Flow](#sih-demo-flow)
- [Operational Limitations](#operational-limitations)
- [Roadmap](#roadmap)
- [Responsible Use](#responsible-use)
- [Contributing](#contributing)

---

# Why CyberWorld

Most security monitoring systems are optimized around **detection and response**. CyberWorld adds a forecasting layer.

Instead of treating a network event as an isolated alert, CyberWorld converts traffic into a sequence of time-windowed network states and asks:

1. **What is happening now?**
2. **What is the model forecasting next?**
3. **Which attack stage is most likely?**
4. **Which telemetry features contributed to the risk estimate?**
5. **What could happen under an alternative scenario?**
6. **What response options are available to an analyst?**

This makes CyberWorld a **predictive SOC decision-support system**, rather than only another alert dashboard.

---

# Core Problem

Modern SOC teams deal with:

- high alert volume,
- fragmented telemetry,
- limited context around attack progression,
- reactive detection workflows,
- difficult-to-explain ML predictions,
- and a gap between model output and analyst action.

CyberWorld addresses that gap by connecting a temporal ML model with:

- network telemetry processing,
- attack forecasting,
- stage classification,
- feature attribution,
- incident investigation,
- counterfactual what-if analysis,
- MITRE ATT&CK mapping,
- IOC enrichment,
- AI-assisted analyst workflows,
- and guarded response automation.

---

# What CyberWorld Does

### 1. Observes network activity
Accepts network telemetry from CSV/flow-style data and supports live packet monitoring through the backend sniffer path.

### 2. Builds temporal network states
Traffic is aggregated into configurable windows. The current default is a **10-second window** with a **33-dimensional feature representation**.

### 3. Learns temporal behavior
A **2-layer PyTorch LSTM** processes a rolling sequence of network states.

### 4. Forecasts future risk
The model produces attack-risk probabilities and supports autoregressive multi-step forecasting.

### 5. Classifies attack stage
The model includes a multi-class stage head covering CyberWorld's six operational stages:

- `BENIGN`
- `RECONNAISSANCE`
- `INITIAL_ACCESS`
- `LATERAL_MOVEMENT`
- `COMMAND_AND_CONTROL`
- `EXFILTRATION`

### 6. Explains predictions
CyberWorld exposes feature-attribution analysis using permutation importance, with optional Captum support in the model stack.

### 7. Supports analyst investigation
Alerts, notes, timelines, cases, evidence, and enrichment are persisted through the backend.

### 8. Runs what-if simulations
Analysts can perturb a scenario and compare the resulting model trajectory against the baseline trajectory.

### 9. Connects forecasts to response
The active-defense layer can generate guarded firewall actions with whitelist protections, rollback, and auto-expiry behavior.

### 10. Provides an AI SOC Copilot
Gemini is accessed through a **server-side proxy**, keeping provider credentials out of the browser.

---

# System Architecture

```text
                         ┌──────────────────────────┐
                         │   Network Telemetry      │
                         │ CSV / Flow / PCAP / Live │
                         └────────────┬─────────────┘
                                      │
                                      ▼
                    ┌────────────────────────────────┐
                    │ Chronological Feature Pipeline │
                    │ 10s windows • 33 features     │
                    └───────────────┬────────────────┘
                                    │
                                    ▼
                    ┌────────────────────────────────┐
                    │      Sequence Buffer            │
                    │ S(t-9) ... S(t)                │
                    └───────────────┬────────────────┘
                                    │
                                    ▼
                    ┌────────────────────────────────┐
                    │  2-Layer LSTM World Model       │
                    │      Hidden size: 128           │
                    └───────┬───────────┬─────────────┘
                            │           │
             ┌──────────────┘           └──────────────────┐
             ▼                                             ▼
   ┌────────────────────┐                      ┌──────────────────────┐
   │ Attack-Risk Head   │                      │ Stage Classification │
   │ Binary probability │                      │ 6 operational stages │
   └─────────┬──────────┘                      └──────────┬───────────┘
             │                                            │
             └────────────────┬───────────────────────────┘
                              ▼
                 ┌────────────────────────────┐
                 │ Multi-step Forecast / Rollout│
                 └────────────┬───────────────┘
                              │
                              ▼
              ┌──────────────────────────────────┐
              │ Explainability + MITRE Grounding │
              └──────────────┬───────────────────┘
                             │
                             ▼
          ┌─────────────────────────────────────────────┐
          │          Multi-Factor Threat Scoring        │
          └──────────────────────┬──────────────────────┘
                                 │
         ┌───────────────────────┼─────────────────────────┐
         ▼                       ▼                         ▼
┌────────────────┐     ┌──────────────────┐      ┌──────────────────┐
│ SOC Dashboard  │     │ What-If Simulator│      │ Active Defense   │
│ + Investigations│    │ Counterfactuals │      │ + SOAR Controls  │
└────────────────┘     └──────────────────┘      └──────────────────┘
         │
         ▼
┌─────────────────────┐
│ Gemini SOC Copilot  │
│ Server-side proxy   │
└─────────────────────┘
```

---

# Core Components

| Component | Implementation | Role |
|---|---|---|
| SOC Dashboard | React 19 + TypeScript + Vite + Tailwind | Analyst workstation |
| Backend | FastAPI + Python | API, inference, ingestion, copilot proxy |
| World Model | PyTorch LSTM | Temporal attack forecasting |
| Feature Pipeline | Custom Python | 33-dimensional network-state extraction |
| Explainability | Permutation importance + optional Captum | Feature attribution |
| Storage | SQLite | Alerts, cases, notes, investigations |
| Threat Intelligence | AbuseIPDB / OTX integrations | IOC enrichment |
| Security Layer | API key auth + rate limiting + input controls | API protection |
| Deployment | Docker Compose + Nginx | Local/production-style deployment |
| CI | GitHub Actions | Automated validation |

---

# Key Capabilities

## Predictive Attack Forecasting
- Temporal network-state modeling
- Binary attack-risk estimation
- Multi-step autoregressive rollout
- Configurable forecasting horizon
- Attack-stage classification

## SOC Operations
- Alert triage
- Incident timelines
- Investigation cases
- Analyst notes
- Evidence-oriented workflows
- Threat scoring
- Recommendation engine

## Explainable Security Analytics
- Feature attribution over the 33-dimensional state
- Feature-level contribution visualization
- MITRE ATT&CK technique grounding
- Risk reasoning that can be reviewed by analysts

## What-If / Counterfactual Analysis
- Perturb network conditions
- Re-run model inference
- Compare forecast trajectories
- Evaluate hypothetical mitigations before applying them

## Active Defense
- Guarded firewall-rule generation
- Windows and Linux response paths
- Safety whitelist
- 30-minute auto-expiry
- Human rollback

## Live Network Monitoring
- Real-time packet capture path
- Adapter/interface awareness
- Windowed telemetry aggregation
- Attack-signature injection for controlled demonstrations

## AI SOC Copilot
- Server-proxied Gemini integration
- Natural-language analyst assistance
- Alert filtering
- Security context support

---

# Machine Learning Pipeline

## Input representation

CyberWorld converts flow-style network telemetry into a temporal state:

```text
Raw network flows
        ↓
10-second aggregation window
        ↓
33 engineered features
        ↓
standardized feature vector S(t)
        ↓
rolling sequence of 10 states
        ↓
LSTM
```

## Default model configuration

| Parameter | Value |
|---|---:|
| Input features | 33 |
| Sequence length | 10 |
| LSTM layers | 2 |
| Hidden dimension | 128 |
| Dropout | 0.30 |
| Optimizer | AdamW |
| Default learning rate | 0.001 |
| Batch size | 32 |
| Gradient clipping | 1.0 |
| Split | Chronological 70 / 15 / 15 |
| Scaling | StandardScaler fitted on training data |
| Early stopping | Enabled |

## Multi-task learning

The model is trained with three objectives:

```text
Total loss =
    Attack BCE loss
  + Stage Cross-Entropy loss
  + Next-State MSE loss
```

This allows the LSTM to jointly model:

- attack likelihood,
- attack-stage behavior,
- and the next network-state representation.

## Leakage-aware training

CyberWorld uses chronological splits rather than an uncontrolled random split.

The intended separation is:

```text
70% Training
15% Validation
15% Test
```

The scaler is fitted on the training partition and reused for validation/test/inference.

---

# Model Evaluation

The repository contains an explicit evaluation artifact at:

```text
artifacts/configs/evaluation_results.json
```

The current benchmark artifact reports results on **209 held-out test sequences**.

| Metric | Current result |
|---|---:|
| Precision | **80.0%** |
| Recall | **90.0%** |
| Binary F1 | **84.7%** |
| ROC-AUC | **93.46%** |
| PR-AUC | **94.38%** |
| False Positive Rate | **13.95%** |
| False Negative Rate | **10.00%** |

### Stage classification

The current artifact also reports stage-level performance. The aggregate results are:

| Measure | Result |
|---|---:|
| Stage accuracy | **64.11%** |
| Macro F1 | **37.42%** |
| Weighted F1 | **64.25%** |

These figures are important: binary attack-risk forecasting is currently stronger than the six-class stage classifier. That limitation is documented rather than hidden.

### Evaluation philosophy

CyberWorld intentionally separates:

- model training,
- held-out evaluation,
- dashboard presentation,
- and runtime inference.

The dashboard should surface evaluation artifacts produced by the backend rather than hardcoded demo numbers.

---

# Dataset

## CIC-IDS2017

CyberWorld uses **CIC-IDS2017** as its primary public intrusion-detection dataset.

Dataset source:

https://www.unb.ca/cic/datasets/ids-2017.html

### Expected preparation

1. Download the MachineLearningCVE CSV files.
2. Place them under a local dataset directory such as:

```text
data/cic-ids2017/
```

3. Pass the directory to the training pipeline.

Example:

```powershell
python cyberworld/training/train.py `
  --data_dir data/cic-ids2017 `
  --epochs 25
```

### Label mapping

CyberWorld maps CIC-IDS2017 labels into six operational stages:

| CIC-IDS2017 label family | CyberWorld stage |
|---|---|
| BENIGN | BENIGN |
| Bot, PortScan | RECONNAISSANCE |
| FTP-Patator, SSH-Patator, Brute Force variants | INITIAL_ACCESS |
| XSS, SQL Injection, Infiltration | LATERAL_MOVEMENT |
| DoS variants, DDoS, Heartbleed | COMMAND_AND_CONTROL |

**Important:** this stage mapping is an operational abstraction for CyberWorld. CIC-IDS2017 labels are not a one-to-one representation of the MITRE ATT&CK enterprise attack lifecycle.

---

# MITRE ATT&CK Grounding

CyberWorld connects predicted stages and observed telemetry to MITRE ATT&CK techniques used by the SOC views.

Examples shown by the platform include:

- **T1046 — Network Service Scanning**
- **T1110 — Brute Force**
- **T1021 — Remote Services**

This mapping is intended to improve analyst context and response planning.

It should be treated as **threat-intelligence grounding**, not as proof that an ML prediction establishes a specific ATT&CK technique with certainty.

---

# Security Architecture

CyberWorld treats its own control plane as a security boundary.

## Implemented controls

| Control | Implementation |
|---|---|
| Gemini secret handling | Server-side proxy |
| API authentication | Optional `X-API-Key` middleware |
| Rate limiting | Token-bucket protection for Copilot routes |
| Upload limits | 50 MB limit |
| Environment secrets | `.env` / environment variables |
| Frontend secret protection | No provider secret in `VITE_*` variables |
| Deployment | Reverse proxy + isolated Docker services |
| Active defense | Safety whitelist + rollback + auto-expiry |

### Credential hygiene

**Never commit `.env` files or provider keys.**

A previously exposed Gemini key must be revoked and regenerated at the provider console even after it has been removed from source code.

For deployment, provide secrets through the environment:

```powershell
$env:GEMINI_API_KEY="your-key"
$env:CYBERWORLD_API_KEY="your-api-key"
```

---

# Technology Stack

### Frontend
- React 19
- TypeScript
- Vite
- Tailwind CSS

### Backend
- Python
- FastAPI
- Uvicorn
- Pydantic

### Machine Learning
- PyTorch
- scikit-learn
- NumPy
- pandas

### Cybersecurity
- Scapy / live packet capture path
- MITRE ATT&CK mappings
- AbuseIPDB / OTX enrichment
- OS firewall integration

### Data / Storage
- SQLite
- CSV/flow ingestion
- CIC-IDS2017

### Infrastructure
- Docker
- Docker Compose
- Nginx
- GitHub Actions

---

# Project Structure

```text
.
├── src/                              # React SOC dashboard
│   ├── api/                          # Frontend API clients
│   ├── components/                   # SOC views and panels
│   ├── engine/                       # Client-side simulation / local workflows
│   ├── mockData/                     # Controlled demo scenarios
│   ├── App.tsx                       # Application shell
│   └── types.ts                      # Shared frontend types
│
├── cyberworld/
│   ├── app/                          # Application entrypoints
│   ├── backend/
│   │   ├── api.py                    # FastAPI routes
│   │   ├── ingestion.py              # Telemetry ingestion
│   │   ├── live_sniffer.py           # Live traffic capture
│   │   └── enrichment.py             # IOC enrichment
│   │
│   ├── cybersecurity/
│   │   ├── active_defense.py         # Guarded response actions
│   │   ├── alert_engine.py           # Alert lifecycle
│   │   ├── mitre.py                  # ATT&CK grounding
│   │   ├── recommendations.py        # Response recommendations
│   │   └── threat_scoring.py         # Risk scoring
│   │
│   ├── data/
│   │   ├── cic_ids_loader.py         # CIC-IDS2017 loader
│   │   ├── generate_sample.py        # Sample telemetry
│   │   └── feature_engineering/
│   │       └── pipeline.py           # 33-feature state extraction
│   │
│   ├── models/
│   │   ├── world_model.py            # PyTorch LSTM
│   │   ├── forecasting.py             # Rollout / forecasting
│   │   ├── baseline.py               # Baseline models
│   │   └── explainability.py         # Attribution
│   │
│   ├── training/
│   │   ├── dataset.py                # Training dataset utilities
│   │   ├── train.py                  # Training pipeline
│   │   └── evaluate.py               # Held-out evaluation
│   │
│   ├── storage/
│   │   └── database.py               # SQLite persistence
│   │
│   ├── tests/
│   │   └── test_suite.py             # Automated test suite
│   │
│   └── requirements.txt
│
├── artifacts/
│   ├── models/
│   │   └── cyberworld_model.pt       # Trained checkpoint
│   └── configs/
│       ├── model_config.json
│       └── evaluation_results.json
│
├── docker-compose.yml
├── Dockerfile
├── nginx.conf
├── package.json
└── README.md
```

---

# Quick Start

## Option A — Docker Compose

Prerequisites:

- Docker Desktop
- Docker Compose

Set server-side secrets when required:

```powershell
$env:GEMINI_API_KEY="your-gemini-api-key"
$env:CYBERWORLD_API_KEY="your-api-key"
```

Build and launch:

```powershell
docker compose up --build
```

Services:

| Service | URL |
|---|---|
| SOC Dashboard | http://localhost:3000 |
| Backend API | http://localhost:8000 |
| Swagger Docs | http://localhost:8000/docs |
| Health Check | http://localhost:8000/api/health |

Stop:

```powershell
docker compose down
```

---

# Manual Local Development

## Prerequisites

- Node.js >= 18
- npm
- Python >= 3.10
- PyTorch >= 2.1

## 1. Frontend

```powershell
npm install
```

## 2. Backend

```powershell
pip install -r cyberworld/requirements.txt
```

## 3. Environment

Backend:

```powershell
copy cyberworld\.env.example cyberworld\.env
```

Set:

```text
GEMINI_API_KEY=your-server-side-key
CYBERWORLD_API_KEY=your-api-key
ABUSEIPDB_API_KEY=optional
```

Frontend:

```powershell
copy .env.example .env.local
```

Typical local setting:

```text
VITE_API_BASE_URL=http://localhost:8000
```

**Never place secret credentials in `VITE_*` variables.**

## 4. Train or load the model

```powershell
python cyberworld/training/train.py --epochs 25
```

Or with CIC-IDS2017:

```powershell
python cyberworld/training/train.py `
  --data_dir data/cic-ids2017 `
  --epochs 25
```

## 5. Start the backend

```powershell
cd cyberworld
uvicorn backend.api:app --host 0.0.0.0 --port 8000 --reload
```

## 6. Start the dashboard

From the repository root:

```powershell
npm run dev
```

---

# Training

A representative training configuration:

```powershell
python cyberworld/training/train.py `
  --data_dir data/cic-ids2017 `
  --epochs 25 `
  --batch_size 32 `
  --lr 0.001 `
  --hidden_dim 128 `
  --num_layers 2 `
  --seq_len 10 `
  --output_dir artifacts
```

The training pipeline supports:

- real PyTorch gradient-based optimization,
- multi-task loss,
- AdamW optimization,
- learning-rate scheduling,
- early stopping,
- gradient clipping,
- class weighting for stage imbalance,
- chronological splitting,
- training-only feature scaling,
- checkpoint generation.

Generated artifacts:

```text
artifacts/
├── models/
│   └── cyberworld_model.pt
└── configs/
    └── model_config.json
```

---

# Evaluation

Run the explicit evaluation pipeline:

```powershell
python cyberworld/training/evaluate.py `
  --checkpoint artifacts/models/cyberworld_model.pt `
  --data_dir artifacts/test_traffic.csv
```

The evaluation artifact is written to:

```text
artifacts/configs/evaluation_results.json
```

Metrics include:

- Precision
- Recall
- F1
- ROC-AUC
- PR-AUC
- False Positive Rate
- False Negative Rate
- Classification report
- Per-stage metrics

### Recommended benchmark discipline

For research or SIH evaluation:

1. Keep the final test split isolated.
2. Select thresholds using validation data.
3. Record dataset version and split configuration.
4. Report class distribution.
5. Report both binary and stage-level performance.
6. Never replace measured results with hand-entered dashboard values.

---

# API Reference

## Model

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/health` | Health check |
| `GET` | `/api/model/status` | Model state and metrics |
| `POST` | `/api/model/predict` | Single-step prediction |
| `POST` | `/api/model/forecast` | Multi-step forecast |
| `POST` | `/api/model/explain` | Feature attribution |
| `POST` | `/api/model/full-inference` | Prediction + forecast + explanation |
| `GET` | `/api/benchmarks` | Evaluation metrics |

## Ingestion

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/ingest/csv` | CSV telemetry ingestion |
| `POST` | `/api/ingest/pcap` | PCAP ingestion |

## Security / SOC

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/api/copilot/ask` | Server-proxied Gemini Copilot |
| `POST` | `/api/copilot/filter` | Natural-language alert filtering |
| `POST` | `/api/enrich/ip` | IOC enrichment |
| `GET` | `/api/alerts` | List alerts |
| `GET` | `/api/alerts/{id}` | Alert details |

### Authentication

Set:

```text
CYBERWORLD_API_KEY=your-key
```

Send:

```http
X-API-Key: your-key
```

POST/PUT/DELETE routes are protected when authentication is enabled. Health and public GET paths remain available as configured by the backend.

---

# Testing

Run the automated suite:

```powershell
python cyberworld/tests/test_suite.py -v
```

Or:

```powershell
python -m pytest cyberworld/tests/test_suite.py -v
```

The repository test suite covers areas including:

- feature extraction,
- temporal sequencing,
- synthetic-data integrity,
- PyTorch model behavior,
- gradients and checkpoints,
- training-loop behavior,
- threat scoring,
- alert lifecycle,
- MITRE mapping,
- recommendations,
- database persistence,
- explainability,
- API security,
- anti-fabrication checks,
- CIC-IDS loading,
- chronological splitting,
- live sniffer paths,
- active defense,
- API health/model endpoints.

The project repository currently documents **46 automated tests** across these areas.

---

# SIH Demo Flow

CyberWorld is easiest to communicate to judges as an end-to-end security workflow rather than as a collection of disconnected features.

## 1. Show the problem

Start with the distinction:

```text
Reactive security:
event → alert → investigate → respond

CyberWorld:
event → model state → forecast → explain → simulate → respond
```

## 2. Show live telemetry

Open **Live Network Monitor** and demonstrate the packet-capture path and windowed feature aggregation.

For a controlled demo, use the project's attack-signature injection workflow rather than real malicious activity.

## 3. Show the forecast

Open the forecasting view and show:

- current attack-risk probability,
- predicted trajectory,
- future stages,
- confidence/uncertainty where exposed.

## 4. Show why the model made the forecast

Open **Explainability** and show feature-attribution output for the current prediction.

## 5. Show a what-if scenario

Open **What-If Simulator**.

Change a controllable feature or mitigation assumption and compare the baseline forecast against the perturbed trajectory.

The important message is:

> CyberWorld does not only ask "Is this dangerous?" It also supports "What could happen next, and how might the trajectory change under a different action?"

## 6. Show controlled response

Demonstrate the active-defense workflow in a safe environment:

- guarded firewall rule generation,
- safety whitelist,
- auto-expiry,
- human rollback.

## 7. Finish with empirical evidence

Open **Benchmark View** and show the evaluation artifact rather than relying on verbal claims.

Current benchmark artifact:

```text
F1      : 84.7%
ROC-AUC : 93.46%
PR-AUC  : 94.38%
Tests   : 46 automated test cases documented
```

Also acknowledge the weaker stage-classification performance and the limitations of CIC-IDS2017. This makes the technical story more defensible.

---

# Operational Limitations

CyberWorld is an advanced prototype / research-oriented SOC platform, not a claim of universal enterprise detection accuracy.

### Dataset limitations
CIC-IDS2017 is a controlled benchmark dataset. Performance on real enterprise networks may differ.

### Representation limitations
The LSTM operates on engineered aggregate network features rather than raw packet bytes.

### Stage-mapping limitations
CIC-IDS2017 labels do not map perfectly to a real-world kill chain or MITRE ATT&CK progression.

### Forecasting limitations
A high-risk forecast is a probabilistic model output, not a guarantee that a specific future event will occur.

### What-if limitations
Counterfactual trajectories represent model behavior under perturbed inputs. They are not causal proof of real-world outcomes.

### Exfiltration limitations
The project exposes a six-stage operational schema, but CIC-IDS2017 does not provide a clean training basis for every stage, especially exfiltration.

### Deployment limitations
SQLite is appropriate for a self-contained deployment and prototype workflow; higher-concurrency enterprise deployments should move persistence to a production database.

---

# Roadmap

## Near term
- stronger temporal validation on additional datasets,
- improved rare-stage performance,
- calibration of forecast probabilities,
- additional baseline comparisons,
- richer model monitoring.

## Medium term
- streaming feature pipelines,
- drift detection,
- configurable multi-tenant storage,
- production database support,
- stronger IAM,
- model registry/versioning.

## Research direction
- transformer/temporal-attention alternatives,
- graph-based network modeling,
- event-level attack chains,
- uncertainty estimation,
- cross-dataset generalization,
- human-in-the-loop response optimization.

---

# Responsible Use

CyberWorld is intended for:

- controlled security research,
- authorized SOC environments,
- defensive monitoring,
- incident investigation,
- security demonstrations,
- and educational / hackathon use.

Active-defense features should only be executed on systems and networks you are authorized to administer.

For demonstrations, prefer isolated test environments and synthetic or controlled attack scenarios.

---

# Contributing

Contributions should preserve the project's core engineering principles:

1. **Measured over claimed** — expose computed metrics rather than hardcoding results.
2. **Reproducible over opaque** — document datasets, splits, configuration, and model versions.
3. **Secure by default** — never commit credentials or expose secrets to the frontend.
4. **Human-in-the-loop** — response automation should provide safety controls and rollback paths.
5. **Evidence-driven** — distinguish observed telemetry, model forecasts, and hypothetical simulations.
6. **Operationally useful** — features should improve analyst understanding or response quality.

---

## Project

**CyberWorld — AI-Based Network Attack Forecasting Using World Models**

Repository:

https://github.com/sawantvinayak473-cyber/cyberworld-network-attack-forecasting

> **Observe the network. Model the state. Forecast the attack. Explain the risk. Simulate the response.**
