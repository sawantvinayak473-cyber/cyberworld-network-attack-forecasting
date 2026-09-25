#!/usr/bin/env python3
"""
CyberWorld — Streamlit Interactive Explorer
Provides offline exploration of generated traffic, state vector timelines,
forecasting trajectories, and MITRE mapping.
"""

import os
import sys

# Ensure proper pathing
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, root_dir)

try:
    import streamlit as st
    STREAMLIT_AVAILABLE = True
except ImportError:
    STREAMLIT_AVAILABLE = False

if not STREAMLIT_AVAILABLE:
    print("Streamlit not installed in current environment. Please install streamlit via requirements.txt.")
    sys.exit(0)

from cyberworld.data.feature_engineering.pipeline import NetworkFeaturePipeline
from cyberworld.models.world_model import WorldModelPredictor
from cyberworld.models.forecasting import ForecastingEngine
from cyberworld.models.explainability import ExplainabilityEngine
from cyberworld.cybersecurity.mitre import MitreMapper
from cyberworld.cybersecurity.threat_scoring import ThreatScorer

st.set_page_config(
    page_title="CyberWorld — Predictive Network Defence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.title("🛡️ CyberWorld: AI World Model Network Attack Forecasting")
st.markdown("*Don't just detect the attack. Forecast where it goes next.*")

st.sidebar.header("Simulation Settings")
window_sec = st.sidebar.selectbox("Window Duration (Sec)", [10, 30, 60], index=0)
horizon_steps = st.sidebar.slider("Forecast Horizon K (Steps)", min_value=1, max_value=10, value=5)

st.info("System operational. For the primary, high-performance interactive SOC experience with live playback, forward trajectory charts, and incident management, use the CyberWorld React Application running on port 3000.")
