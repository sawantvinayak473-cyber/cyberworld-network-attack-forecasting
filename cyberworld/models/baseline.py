#!/usr/bin/env python3
"""CyberWorld — Baseline Model
Implements a Random Forest baseline for attack stage classification."""

import os
import logging
from typing import Dict, Any, Tuple, Union
import numpy as np

logger = logging.getLogger(__name__)

try:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support
    import joblib
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn is not available. Falling back to heuristic baseline.")

class StaticBaselineClassifier:
    """Random Forest baseline for network attack stage classification."""
    
    def __init__(self, n_estimators: int = 100, max_depth: int = 10, random_state: int = 42):
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.random_state = random_state
        self.model = None
        self.is_trained = False
        self.classes = [0, 1, 2, 3] # Normal, Recon, Attack, Exfil
        
        if SKLEARN_AVAILABLE:
            self.model = RandomForestClassifier(
                n_estimators=n_estimators,
                max_depth=max_depth,
                random_state=random_state,
                class_weight='balanced'
            )
            
    def train(self, X_train: np.ndarray, y_train: np.ndarray) -> None:
        if not SKLEARN_AVAILABLE:
            logger.warning("Cannot train without scikit-learn.")
            return
            
        logger.info(f"Training Baseline Random Forest on {len(X_train)} samples...")
        self.model.fit(X_train, y_train)
        self.is_trained = True
        logger.info("Baseline training complete.")
        
    def predict(self, X: np.ndarray) -> np.ndarray:
        if not SKLEARN_AVAILABLE or not self.is_trained:
            return self._heuristic_predict(X)
            
        return self.model.predict(X)
        
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if not SKLEARN_AVAILABLE or not self.is_trained:
            preds = self._heuristic_predict(X)
            probs = np.zeros((len(preds), len(self.classes)))
            for i, p in enumerate(preds):
                probs[i, p] = 1.0
            return probs
            
        return self.model.predict_proba(X)
        
    def _heuristic_predict(self, X: np.ndarray) -> np.ndarray:
        """Fallback prediction when model is not trained or sklearn unavailable."""
        preds = []
        for row in X:
            val = np.sum(row)
            if val > 1000:
                preds.append(2) # Attack
            elif val > 500:
                preds.append(1) # Recon
            else:
                preds.append(0) # Normal
        return np.array(preds)

    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, float]:
        if not SKLEARN_AVAILABLE or not self.is_trained:
            logger.warning("Evaluating fallback heuristic.")
            
        y_pred = self.predict(X_test)
        
        if SKLEARN_AVAILABLE:
            acc = accuracy_score(y_test, y_pred)
            p, r, f, _ = precision_recall_fscore_support(y_test, y_pred, average='weighted', zero_division=0)
            return {
                'accuracy': float(acc),
                'precision': float(p),
                'recall': float(r),
                'f1_score': float(f)
            }
        else:
            acc = np.mean(y_pred == y_test)
            return {'accuracy': float(acc), 'precision': 0.0, 'recall': 0.0, 'f1_score': 0.0}
            
    def save(self, path: str) -> None:
        if not SKLEARN_AVAILABLE:
            return
            
        if self.is_trained:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            joblib.dump(self.model, path)
            logger.info(f"Model saved to {path}")
            
    def load(self, path: str) -> bool:
        if not SKLEARN_AVAILABLE:
            return False
            
        if os.path.exists(path):
            self.model = joblib.load(path)
            self.is_trained = True
            logger.info(f"Model loaded from {path}")
            return True
        return False
