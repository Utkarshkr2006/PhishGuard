"""
PhishGuard 2.0 - Realistic Prediction Sanity Check Test Suite
Module: analysis/test_predictor_realistic.py

Evaluates predict_url() against benign, moderately suspicious, and obviously suspicious URLs
to test model probability behavior and variation across non-extreme inputs.
"""

import sys
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from analysis.predictor import predict_url

TEST_GROUPS = [
    {
        "group_name": "BENIGN / COMMON URLs",
        "urls": [
            "https://www.wikipedia.org",
            "https://github.com/login",
            "https://accounts.google.com",
            "https://www.amazon.in",
            "https://example.com/products?id=12345",
            "http://example.com"
        ]
    },
    {
        "group_name": "MODERATELY SUSPICIOUS URLs",
        "urls": [
            "https://example.com/login/verify",
            "https://secure-example.com/account",
            "https://example.com/user/12345",
            "https://example.com/verify/account"
        ]
    },
    {
        "group_name": "OBVIOUSLY SUSPICIOUS URLs",
        "urls": [
            "http://secure-login-verify-account.bank-update.xyz/login.php?user=123&token=abc",
            "http://192.168.1.100/admin/login",
            "http://admin:secret@phishing-target.com/account"
        ]
    }
]

def run_sanity_check():
    print("==========================================================")
    print("     PHISHGUARD 2.0 - PREDICTION ENGINE SANITY CHECK")
    print("==========================================================\n")

    all_phishing_probs = []

    for group in TEST_GROUPS:
        group_name = group["group_name"]
        print(f"=== {group_name} ===")

        for url in group["urls"]:
            res = predict_url(url)
            pred_class = res["prediction"]
            phish_prob = res["phishing_probability"]
            legit_prob = res["legitimate_probability"]
            
            all_phishing_probs.append(phish_prob)

            print(f"URL:                  {url}")
            print(f"  --> Prediction:     {pred_class}")
            print(f"  --> Phishing Prob:  {phish_prob:.4f} ({phish_prob * 100:.2f}%)")
            print(f"  --> Legit Prob:     {legit_prob:.4f} ({legit_prob * 100:.2f}%)")
            print()

    # Calculate requested aggregate stats
    min_phish_prob = min(all_phishing_probs)
    max_phish_prob = max(all_phishing_probs)
    count_exact_0 = sum(1 for p in all_phishing_probs if p == 0.0)
    count_exact_1 = sum(1 for p in all_phishing_probs if p == 1.0)
    total_urls = len(all_phishing_probs)

    print("==========================================================")
    print("           SANITY CHECK AGGREGATE STATISTICS")
    print("==========================================================")
    print(f"  Total URLs Evaluated:                    {total_urls}")
    print(f"  Minimum Phishing Probability:           {min_phish_prob:.4f} ({min_phish_prob * 100:.2f}%)")
    print(f"  Maximum Phishing Probability:           {max_phish_prob:.4f} ({max_phish_prob * 100:.2f}%)")
    print(f"  Predictions with Phishing Prob == 0.0:   {count_exact_0} / {total_urls} ({count_exact_0/total_urls*100:.1f}%)")
    print(f"  Predictions with Phishing Prob == 1.0:   {count_exact_1} / {total_urls} ({count_exact_1/total_urls*100:.1f}%)")
    print("==========================================================\n")

if __name__ == '__main__':
    run_sanity_check()
