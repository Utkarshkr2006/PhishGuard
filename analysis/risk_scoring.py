"""
PhishGuard 2.0 - Risk Assessment Engine
Module: analysis/risk_scoring.py

Calculates a deterministic composite cybersecurity risk score (0-100) and risk level
(LOW, MEDIUM, HIGH, CRITICAL) by combining observable lexical URL indicators,
co-occurrence combination rules, and ML model supporting signals.

NOTE & DISCLAIMER:
- The Risk Score is a heuristic composite metric bounded between 0 and 100.
- It is NOT a calibrated statistical probability.
- The ML prediction is treated as one input signal among multiple observable security rules.
- HTTPS encryption does not automatically guarantee site legitimacy.
"""

import os
import sys

# Ensure parent directory is in path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

# Risk Level Threshold Definitions
THRESHOLD_LOW = 24       # 0 - 24
THRESHOLD_MEDIUM = 49    # 25 - 49
THRESHOLD_HIGH = 74      # 50 - 74
                         # 75 - 100 -> CRITICAL

def calculate_risk_score(prediction_result: dict, explanation_result: dict) -> dict:
    """
    Computes a composite risk score (0-100), risk level, agreement label, top reasons,
    summary, and recommendation for an analyzed URL.
    
    Parameters:
        prediction_result (dict): Output from predict_url(url).
        explanation_result (dict): Output from explain_prediction(prediction_result).
        
    Returns:
        dict: {
            "risk_score": int,
            "risk_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
            "confidence_label": str,
            "top_reasons": list[str],
            "summary": str,
            "recommendation": str
        }
    """
    if not isinstance(prediction_result, dict) or not isinstance(explanation_result, dict):
        raise ValueError("Invalid input parameters: expected dictionaries for prediction and explanation.")

    url = prediction_result.get("url", "")
    features = prediction_result.get("features", {})
    model_pred = prediction_result.get("prediction", "Unknown")
    model_says_phishing = (model_pred == "Phishing")

    risk_indicators = explanation_result.get("risk_indicators", [])
    positive_signals = explanation_result.get("positive_signals", [])

    base_score = 0

    # -----------------------------------------------------------------
    # 1. STRONG RISK INDICATORS (High Weight)
    # -----------------------------------------------------------------
    if features.get("is_domain_ip", 0) == 1:
        base_score += 30

    if features.get("num_at_symbols", 0) > 0:
        base_score += 25

    if features.get("has_suspicious_tld", 0) == 1:
        base_score += 25

    if features.get("has_url_encoding", 0) == 1:
        base_score += 20

    if features.get("url_entropy", 0.0) > 4.8:
        base_score += 15

    # -----------------------------------------------------------------
    # 2. MODERATE RISK INDICATORS (Moderate Weight)
    # -----------------------------------------------------------------
    if features.get("has_suspicious_keywords", 0) == 1:
        base_score += 15

    if features.get("num_subdomains", 0) >= 3:
        base_score += 15

    if features.get("digit_ratio", 0.0) > 0.10 or features.get("num_digits", 0) > 5:
        base_score += 15

    if features.get("num_hyphens", 0) >= 3:
        base_score += 10

    if features.get("url_length", 0) > 75:
        base_score += 10

    if features.get("num_equals", 0) > 1 or features.get("num_ampersands", 0) > 1:
        base_score += 10

    # -----------------------------------------------------------------
    # 3. HTTP / HTTPS PROTOCOL EVALUATION
    # -----------------------------------------------------------------
    if features.get("is_https", 0) == 0:
        base_score += 15  # Unencrypted HTTP connection penalty

    # -----------------------------------------------------------------
    # 4. ML MODEL SUPPORTING SIGNAL
    # -----------------------------------------------------------------
    # Treat ML prediction as one supporting signal (+15 points if model predicts Phishing)
    if model_says_phishing:
        base_score += 15

    # -----------------------------------------------------------------
    # 5. CO-OCCURRENCE & COMBINATION RULES (Escalation Multipliers)
    # -----------------------------------------------------------------
    num_risk_count = len(risk_indicators)
    
    if num_risk_count >= 5:
        base_score += 20
    elif num_risk_count >= 3:
        base_score += 10

    # IP + HTTP + Keyword escalation
    if features.get("is_domain_ip", 0) == 1 and features.get("has_suspicious_keywords", 0) == 1:
        base_score += 15

    # HTTP + Suspicious TLD + Keyword escalation
    if (features.get("is_https", 0) == 0 and 
        features.get("has_suspicious_tld", 0) == 1 and 
        features.get("has_suspicious_keywords", 0) == 1):
        base_score += 20

    # -----------------------------------------------------------------
    # 6. POSITIVE SIGNAL DAMPENING
    # -----------------------------------------------------------------
    if features.get("is_https", 0) == 1 and features.get("path_length", 0) == 0:
        if features.get("has_suspicious_keywords", 0) == 0 and features.get("has_suspicious_tld", 0) == 0:
            base_score -= 15

    # -----------------------------------------------------------------
    # 7. BOUNDING & RISK LEVEL MAPPING
    # -----------------------------------------------------------------
    final_risk_score = int(max(0, min(100, base_score)))

    if final_risk_score <= THRESHOLD_LOW:
        risk_level = "LOW"
    elif final_risk_score <= THRESHOLD_MEDIUM:
        risk_level = "MEDIUM"
    elif final_risk_score <= THRESHOLD_HIGH:
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    # -----------------------------------------------------------------
    # 8. AGREEMENT / CONFIDENCE LABEL
    # -----------------------------------------------------------------
    # Measures agreement between ML prediction and rule-based risk count
    if model_says_phishing:
        if num_risk_count >= 3 or final_risk_score >= 50:
            confidence_label = "Strong agreement"
        elif num_risk_count >= 1:
            confidence_label = "Moderate agreement"
        else:
            confidence_label = "Low agreement"
    else:
        if num_risk_count == 0 and final_risk_score <= 24:
            confidence_label = "Strong agreement"
        elif num_risk_count >= 2 or final_risk_score >= 50:
            confidence_label = "Low agreement"
        else:
            confidence_label = "Moderate agreement"

    # -----------------------------------------------------------------
    # 9. TOP REASONS (Max 5) - Strictly Warning/Risk Indicators Only
    # -----------------------------------------------------------------
    top_reasons = [r for r in risk_indicators[:5]]

    # -----------------------------------------------------------------
    # 10. DETERMINISTIC SUMMARY & RECOMMENDATION
    # -----------------------------------------------------------------
    if risk_level == "LOW":
        summary = "No major suspicious indicators were detected in this web address."
        recommendation = "Before entering your password or personal information, make sure the web address belongs to the service you intended to visit."
    elif risk_level == "MEDIUM":
        summary = "Some suspicious characteristics were detected. Exercise caution."
        recommendation = "Before entering passwords or sensitive details, double-check that the domain name is authentic."
    elif risk_level == "HIGH":
        summary = "Multiple suspicious warning signs were detected in this address."
        recommendation = "Do not enter passwords, payment information, or other sensitive information until you have verified the website through an official source."
    else: # CRITICAL
        summary = "Multiple strong warning signs were detected. Treat this address with high caution."
        recommendation = "Do not enter passwords, payment information, or other sensitive information until you have verified the website through an official source."

    return {
        "risk_score": final_risk_score,
        "risk_level": risk_level,
        "confidence_label": confidence_label,
        "top_reasons": top_reasons,
        "summary": summary,
        "recommendation": recommendation
    }
