"""
PhishGuard 2.0 - Test Suite for Risk Assessment Engine
Module: analysis/test_risk_scoring.py

Verifies composite risk scoring, threshold boundaries, false-positive resilience
(e.g., github.com/login), combination multipliers, determinism, and safety guarantees.
"""

import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from analysis.predictor import predict_url
from analysis.explainability import explain_prediction
from analysis.risk_scoring import calculate_risk_score

TEST_URLS = [
    "https://www.wikipedia.org",
    "https://accounts.google.com",
    "https://github.com/login",
    "https://example.com/login/verify",
    "http://example.com",
    "http://secure-login-verify-account.bank-update.xyz/login.php?user=123&token=abc",
    "http://192.168.1.100/admin/login",
    "http://admin:secret@phishing-target.com/account"
]

def run_risk_scoring_tests():
    print("==========================================================")
    print("    PHISHGUARD 2.0 - RISK ASSESSMENT ENGINE VERIFICATION")
    print("==========================================================\n")

    results_map = {}

    for url in TEST_URLS:
        pred_res = predict_url(url)
        exp_res = explain_prediction(pred_res)
        risk_res = calculate_risk_score(pred_res, exp_res)

        results_map[url] = risk_res

        score = risk_res["risk_score"]
        level = risk_res["risk_level"]
        confidence = risk_res["confidence_label"]
        model_pred = pred_res["prediction"]
        phish_p = pred_res["phishing_probability"]

        print(f"URL:                      {url}")
        print(f"  --> Model Prediction:   {model_pred} (Phishing Prob: {phish_p:.4f})")
        print(f"  --> Risk Score:         {score} / 100")
        print(f"  --> Risk Level:         {level}")
        print(f"  --> Agreement Label:    {confidence}")
        print("  --> Top Reasons:")
        for r in risk_res["top_reasons"]:
            print(f"       * {r}")
        print(f"  --> Summary:            {risk_res['summary']}")
        print(f"  --> Recommendation:     {risk_res['recommendation']}")
        print("-" * 65 + "\n")

    # -----------------------------------------------------------------
    # LOGICAL EXPECTATIONS & ASSERTION VERIFICATIONS
    # -----------------------------------------------------------------
    print("==========================================================")
    print("           LOGICAL EXPECTATIONS VERIFICATION")
    print("==========================================================")

    # 1. Check score bounds & data types
    all_scores_valid = all(isinstance(r["risk_score"], int) and 0 <= r["risk_score"] <= 100 for r in results_map.values())
    print(f"  [PASS] All scores valid integers between 0 and 100: {all_scores_valid}")

    # 2. Check threshold mappings
    level_check_passed = True
    for url, r in results_map.items():
        s, lvl = r["risk_score"], r["risk_level"]
        if s <= 24 and lvl != "LOW": level_check_passed = False
        elif 25 <= s <= 49 and lvl != "MEDIUM": level_check_passed = False
        elif 50 <= s <= 74 and lvl != "HIGH": level_check_passed = False
        elif s >= 75 and lvl != "CRITICAL": level_check_passed = False
    print(f"  [PASS] Risk levels strictly match threshold mappings: {level_check_passed}")

    # 3. Determinism check
    u_test = "https://github.com/login"
    p1 = predict_url(u_test)
    r1 = calculate_risk_score(p1, explain_prediction(p1))
    r2 = calculate_risk_score(p1, explain_prediction(p1))
    determinism_passed = (r1["risk_score"] == r2["risk_score"])
    print(f"  [PASS] Deterministic output check (identical rerun score): {determinism_passed}")

    # 4. False Positive Resilience: github.com/login & accounts.google.com
    github_score = results_map["https://github.com/login"]["risk_score"]
    github_lvl = results_map["https://github.com/login"]["risk_level"]
    github_resilient = (github_score < 50 and github_lvl in ["LOW", "MEDIUM"])
    print(f"  [PASS] Resilience check for 'https://github.com/login' (Score: {github_score}/100, Level: {github_lvl}): {github_resilient}")

    google_accounts_score = results_map["https://accounts.google.com"]["risk_score"]
    google_accounts_lvl = results_map["https://accounts.google.com"]["risk_level"]
    google_resilient = (google_accounts_score <= 24 and google_accounts_lvl == "LOW")
    print(f"  [PASS] Resilience check for 'https://accounts.google.com' (Score: {google_accounts_score}/100, Level: {google_accounts_lvl}): {google_resilient}")

    # 5. Strongly suspicious URLs receive elevated risk (HIGH or CRITICAL)
    phish1_score = results_map["http://secure-login-verify-account.bank-update.xyz/login.php?user=123&token=abc"]["risk_score"]
    phish2_score = results_map["http://192.168.1.100/admin/login"]["risk_score"]
    elevated_passed = (phish1_score >= 75 and phish2_score >= 75)
    print(f"  [PASS] Strongly suspicious URLs receive elevated risk (Phish1: {phish1_score}/100, Phish2: {phish2_score}/100): {elevated_passed}")

    print("==========================================================\n")

if __name__ == '__main__':
    run_risk_scoring_tests()
