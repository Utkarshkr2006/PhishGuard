"""
PhishGuard 2.0 - Test Suite for URL Feature Extractor
Module: analysis/test_url_features.py

Tests the 23 lexical URL feature extraction rules against key URL patterns.
"""

from url_features import extract_url_features

TEST_URLS = [
    {
        "category": "1. Normal HTTPS URL",
        "url": "https://www.google.com/search?q=cybersecurity"
    },
    {
        "category": "2. Suspicious Phishing URL",
        "url": "http://secure-login-verify-account.bank-update.xyz/login.php?user=123&token=abc"
    },
    {
        "category": "3. URL containing IP Address",
        "url": "http://192.168.1.100/admin/login"
    },
    {
        "category": "4. URL containing @ Symbol",
        "url": "http://admin:secret@phishing-target.com/account"
    },
    {
        "category": "5. URL with Percent Encoding",
        "url": "http://example.com/path%20with%20spaces%21%23"
    },
    {
        "category": "6. URL with Many Subdomains",
        "url": "http://login.verify.account.update.security.example.com/auth"
    }
]

def run_tests():
    print("==========================================================")
    print("     PHISHGUARD 2.0 - URL FEATURE EXTRACTOR VERIFICATION")
    print("==========================================================\n")
    
    for item in TEST_URLS:
        category = item["category"]
        test_url = item["url"]
        
        print(f"Test Category: {category}")
        print(f"Input URL:     {test_url}")
        print("-" * 58)
        
        features = extract_url_features(test_url)
        
        for feature_name, value in features.items():
            print(f"  {feature_name:<25}: {value}")
        print("\n" + "=" * 58 + "\n")

if __name__ == '__main__':
    run_tests()
