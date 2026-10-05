"""
PhishGuard 2.0 - Inference & Prediction Engine
Module: analysis/predictor.py

Loads the trained Random Forest model and feature schema to predict
phishing vs legitimate classification on raw URL inputs.
"""

import os
import sys
import json
import joblib
import numpy as np

# Ensure parent directory is in path for relative import of url_features
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from analysis.url_features import extract_url_features

MODEL_PATH = os.path.join(BASE_DIR, 'model', 'random_forest.pkl')
FEATURE_NAMES_PATH = os.path.join(BASE_DIR, 'model', 'feature_names.json')

# Module-level cached instances
_MODEL = None
_FEATURE_NAMES = None

def load_prediction_assets():
    """
    Loads model and feature names from disk into memory (singleton pattern).
    """
    global _MODEL, _FEATURE_NAMES
    
    if _MODEL is None:
        if not os.path.exists(MODEL_PATH):
            raise FileNotFoundError(f"Model file not found at {MODEL_PATH}")
        _MODEL = joblib.load(MODEL_PATH)
        
    if _FEATURE_NAMES is None:
        if not os.path.exists(FEATURE_NAMES_PATH):
            raise FileNotFoundError(f"Feature names JSON not found at {FEATURE_NAMES_PATH}")
        with open(FEATURE_NAMES_PATH, 'r') as f:
            _FEATURE_NAMES = json.load(f)
            
    return _MODEL, _FEATURE_NAMES

def predict_url(url: str) -> dict:
    """
    Predicts whether a given URL is Phishing or Legitimate using the trained Random Forest.
    
    Parameters:
        url (str): Input raw URL string.
        
    Returns:
        dict: {
            "url": str,
            "prediction": "Phishing" | "Legitimate",
            "predicted_label": 0 | 1,
            "phishing_probability": float,
            "legitimate_probability": float,
            "features": dict
        }
    """
    if not isinstance(url, str):
        url = str(url) if url is not None else ""
    url = url.strip()

    model, feature_names = load_prediction_assets()
    
    # 1. Extract 23 features using analysis.url_features
    extracted_features = extract_url_features(url)
    
    # 2. Build feature vector in exact feature_names order
    feature_vector = []
    for feature in feature_names:
        if feature not in extracted_features:
            raise ValueError(f"Feature '{feature}' missing from feature extractor output!")
        feature_vector.append(extracted_features[feature])

    X_input = np.array([feature_vector], dtype=float)

    # 3. Model Prediction
    predicted_label = int(model.predict(X_input)[0])
    probabilities = model.predict_proba(X_input)[0]

    # 4. Map probabilities using model.classes_ attribute dynamically
    classes = list(model.classes_)
    phishing_idx = classes.index(0) if 0 in classes else 0
    legit_idx = classes.index(1) if 1 in classes else 1

    phishing_prob = float(probabilities[phishing_idx])
    legit_prob = float(probabilities[legit_idx])

    prediction_text = "Phishing" if predicted_label == 0 else "Legitimate"

    return {
        "url": url,
        "prediction": prediction_text,
        "predicted_label": predicted_label,
        "phishing_probability": round(phishing_prob, 4),
        "legitimate_probability": round(legit_prob, 4),
        "features": extracted_features
    }
