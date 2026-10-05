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
        positive_signals.append("Uses encrypted HTTPS connection protocol")
    else:
        risk_indicators.append("Does not use HTTPS encryption (HTTP connection)")

    # 2. IP Address Domain Detection
    if features.get("is_domain_ip", 0) == 1:
        risk_indicators.append("IP address used directly as the domain instead of a domain name")

    # 3. @ Symbol Obfuscation
    if features.get("num_at_symbols", 0) > 0:
        count_at = features["num_at_symbols"]
        risk_indicators.append(f"URL contains @ symbol ({count_at}), which can obscure the actual destination domain")

    # 4. URL Percent Encoding
    if features.get("has_url_encoding", 0) == 1:
        risk_indicators.append("Encoded characters (%xx) detected in the URL path or query string")

    # 5. Suspicious TLD
    if features.get("has_suspicious_tld", 0) == 1:
        risk_indicators.append("Suspicious-TLD indicator detected (commonly associated with high-risk domain extensions)")

    # 6. Suspicious Keywords
    if features.get("has_suspicious_keywords", 0) == 1:
        risk_indicators.append("Suspicious account/login-related keyword indicator detected")

    # 7. Subdomain Count
    num_subdomains = features.get("num_subdomains", 0)
    if num_subdomains >= 3:
        risk_indicators.append(f"Multiple subdomain levels detected ({num_subdomains} subdomains)")

    # 8. Excessive URL Length
    url_len = features.get("url_length", 0)
    if url_len > 75:
        risk_indicators.append(f"Unusually long URL length detected ({url_len} characters)")

    # 9. Digit Density / Count
    num_digits = features.get("num_digits", 0)
    digit_ratio = features.get("digit_ratio", 0.0)
    if digit_ratio > 0.10 or num_digits > 5:
        risk_indicators.append(f"High numeric digit concentration detected ({num_digits} digits, {digit_ratio * 100:.1f}% digit ratio)")

    # 10. Hyphen Count
    num_hyphens = features.get("num_hyphens", 0)
    if num_hyphens >= 3:
        risk_indicators.append(f"Multiple hyphens detected in domain/path ({num_hyphens} hyphens)")

    # 11. High Character Entropy
    url_entropy = features.get("url_entropy", 0.0)
    if url_entropy > 4.5:
        risk_indicators.append(f"High character entropy ({url_entropy:.2f}), indicating potential URL randomness or obfuscation")

    # 12. Query Parameters
    num_equals = features.get("num_equals", 0)
    num_ampersands = features.get("num_ampersands", 0)
    if num_equals > 1 or num_ampersands > 1:
        risk_indicators.append(f"Complex query parameters detected ({num_equals} '=' and {num_ampersands} '&')")

    # Positive Signal Combinations
    if features.get("is_https", 0) == 1 and features.get("path_length", 0) == 0:
        if features.get("has_suspicious_keywords", 0) == 0 and features.get("has_suspicious_tld", 0) == 0:
            positive_signals.append("Clean root domain structure without suspicious path artifacts")

    # Generate Deterministic Summary & Recommendation
    num_risks = len(risk_indicators)
    
    if prediction == "Phishing" or num_risks >= 2:
        summary = f"Detected {num_risks} threat risk indicator(s) in this URL structure."
        recommendation = "Do not enter sensitive passwords, personal credentials, or payment details. Verify the official website domain directly."
    elif num_risks == 1:
        summary = "Detected 1 potential risk indicator. The URL requires careful review."
        recommendation = "Verify the sender and confirm the domain matches your intended destination before proceeding."
    else:
        summary = "No suspicious structural or lexical risk indicators were detected."
        recommendation = "This link displays standard legitimate structural patterns. Always verify HTTPS connection in your browser."

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
