"""
PhishGuard 2.0 - Phase 7 End-to-End Test Matrix Generator
Generates data/phase7_evaluation_report.csv using the existing pipeline.
"""

import os
import sys
import csv

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from analysis.predictor import predict_url
from analysis.explainability import explain_prediction
from analysis.risk_scoring import calculate_risk_score

URLS = [
    "https://www.wikipedia.org",
    "https://accounts.google.com",
    "https://github.com/login",
    "https://example.com/products?id=12345",
    "http://example.com",
    "https://example.com/login/verify",
    "http://secure-login-verify-account.bank-update.xyz/login.php?user=123&token=abc",
    "http://192.168.1.100/admin/login",
    "http://admin:secret@phishing-target.com/account"
]

OUTPUT_CSV = os.path.join(BASE_DIR, 'data', 'phase7_evaluation_report.csv')

rows = []
for url in URLS:
    pred = predict_url(url)
    exp = explain_prediction(pred)
    risk = calculate_risk_score(pred, exp)
    rows.append({
        "URL": url,
        "Model_Prediction": pred["prediction"],
        "Model_Phishing_Probability": pred["phishing_probability"],
        "Risk_Score": risk["risk_score"],
        "Risk_Level": risk["risk_level"],
        "Top_Indicators": " | ".join(risk["top_reasons"][:3]) if risk["top_reasons"] else "None"
    })
    print(f"  {url[:60]:<62} | {risk['risk_level']:<8} | {risk['risk_score']}/100")

with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as f:
    writer = csv.DictWriter(f, fieldnames=["URL","Model_Prediction","Model_Phishing_Probability","Risk_Score","Risk_Level","Top_Indicators"])
    writer.writeheader()
    writer.writerows(rows)

print(f"\n[+] Saved to {OUTPUT_CSV}")
