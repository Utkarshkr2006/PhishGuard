"""
PhishGuard 2.0 - Rule-Based Explainability Engine
Module: analysis/explainability.py

Generates transparent, deterministic, and evidence-backed explanations
from extracted URL features and model prediction outputs.
"""

import os
import sys

# Ensure parent directory is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

def explain_prediction(prediction_result: dict) -> dict:
    """
    Generates rule-based cybersecurity explanations from prediction results and extracted features.
    
    Parameters:
        prediction_result (dict): The output dictionary returned by predict_url().
        
    Returns:
        dict: {
            "url": str,
            "prediction": str,
            "phishing_probability": float,
            "legitimate_probability": float,
            "risk_indicators": list[str],
            "positive_signals": list[str],
            "summary": str,
            "recommendation": str
        }
    """
    if not isinstance(prediction_result, dict):
        raise ValueError("Invalid prediction result: expected a dictionary.")

    url = prediction_result.get("url", "")
    prediction = prediction_result.get("prediction", "Unknown")
    phish_prob = prediction_result.get("phishing_probability", 0.0)
    legit_prob = prediction_result.get("legitimate_probability", 0.0)
    features = prediction_result.get("features", {})

    risk_indicators = []
    positive_signals = []

    # 1. Protocol Scheme (HTTPS vs HTTP)
    if features.get("is_https", 0) == 1:
        positive_signals.append("Uses a secure HTTPS connection")
    else:
        risk_indicators.append("The connection does not use HTTPS")

    # 2. IP Address Domain Detection
    if features.get("is_domain_ip", 0) == 1:
        risk_indicators.append("Uses a numeric address instead of a normal website name")

    # 3. @ Symbol Obfuscation
    if features.get("num_at_symbols", 0) > 0:
        count_at = features["num_at_symbols"]
        risk_indicators.append(f"Contains an @ symbol ({count_at}), which can hide the real website destination")

    # 4. URL Percent Encoding
    if features.get("has_url_encoding", 0) == 1:
        risk_indicators.append("Contains encoded characters that may hide part of the address")

    # 5. Suspicious TLD
    if features.get("has_suspicious_tld", 0) == 1:
        risk_indicators.append("Uses a less common website ending that can be a warning sign")

    # 6. Suspicious Keywords
    if features.get("has_suspicious_keywords", 0) == 1:
        risk_indicators.append("Contains words commonly used in account or login scams")

    # 7. Subdomain Count
    num_subdomains = features.get("num_subdomains", 0)
    if num_subdomains >= 3:
        risk_indicators.append(f"Uses several levels in the website address ({num_subdomains} levels detected)")

    # 8. Excessive URL Length
    url_len = features.get("url_length", 0)
    if url_len > 75:
        risk_indicators.append(f"The web address is unusually long ({url_len} characters)")

    # 9. Digit Density / Count
    num_digits = features.get("num_digits", 0)
    digit_ratio = features.get("digit_ratio", 0.0)
    if digit_ratio > 0.10 or num_digits > 5:
        risk_indicators.append(f"Contains an unusually high number of numbers ({num_digits} digits)")

    # 10. Hyphen Count
    num_hyphens = features.get("num_hyphens", 0)
    if num_hyphens >= 3:
        risk_indicators.append(f"Contains several hyphens in the address ({num_hyphens} hyphens)")

    # 11. High Character Entropy
    url_entropy = features.get("url_entropy", 0.0)
    if url_entropy > 4.5:
        risk_indicators.append("Contains unusually complex characters, which can be a warning sign")

    # 12. Query Parameters
    num_equals = features.get("num_equals", 0)
    num_ampersands = features.get("num_ampersands", 0)
    if num_equals > 1 or num_ampersands > 1:
        risk_indicators.append("Contains complex parameters that may hide part of the address")

    # Positive Signal Combinations
    if features.get("is_https", 0) == 1 and features.get("path_length", 0) == 0:
        if features.get("has_suspicious_keywords", 0) == 0 and features.get("has_suspicious_tld", 0) == 0:
            positive_signals.append("Website address looks simple and clean")

    # Generate Deterministic Summary & Recommendation
    num_risks = len(risk_indicators)
    
    if prediction == "Phishing" or num_risks >= 2:
        summary = f"Detected {num_risks} warning sign(s) in this web address."
        recommendation = "Do not enter passwords, payment information, or other sensitive information until you have verified the website through an official source."
    elif num_risks == 1:
        summary = "Detected 1 potential warning sign in this web address."
        recommendation = "Before entering your password or personal information, make sure the web address belongs to the service you intended to visit."
    else:
        summary = "No suspicious indicators were detected in this web address."
        recommendation = "Before entering your password or personal information, make sure the web address belongs to the service you intended to visit."

    return {
        "url": url,
        "prediction": prediction,
        "phishing_probability": phish_prob,
        "legitimate_probability": legit_prob,
        "risk_indicators": risk_indicators,
        "positive_signals": positive_signals,
        "summary": summary,
        "recommendation": recommendation
    }
