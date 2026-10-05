import os
import sys
import json
import numpy as np
import pandas as pd

# Add current directory to import url_features module
sys.path.append(os.path.dirname(__file__))
from url_features import extract_url_features

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
CSV_PATH = os.path.join(DATA_DIR, 'PhiUSIIL_Phishing_URL_Dataset.csv')
REPORT_CSV_PATH = os.path.join(DATA_DIR, 'feature_validation_report.csv')
SUMMARY_JSON_PATH = os.path.join(DATA_DIR, 'feature_validation_summary.json')

EXPECTED_FEATURES = [
    "url_length", "domain_length", "path_length", "num_dots",
    "num_subdomains", "num_digits", "num_letters", "num_hyphens",
    "num_special_chars", "num_at_symbols", "num_question_marks",
    "num_equals", "num_ampersands", "num_slashes", "is_https",
    "is_domain_ip", "has_suspicious_keywords", "has_url_encoding",
    "has_suspicious_tld", "letter_ratio", "digit_ratio",
    "special_char_ratio", "url_entropy"
]

BINARY_FEATURES = [
    "is_https", "is_domain_ip", "has_suspicious_keywords",
    "has_url_encoding", "has_suspicious_tld"
]

def run_validation(sample_size=10000, random_seed=42):
    print("==========================================================")
    print("    PHISHGUARD 2.0 - FEATURE EXTRACTOR VALIDATION")
    print("==========================================================\n")

    if not os.path.exists(CSV_PATH):
        raise FileNotFoundError(f"Dataset not found at {CSV_PATH}")

    print(f"[*] Loading dataset from {CSV_PATH}...")
    full_df = pd.read_csv(CSV_PATH)
    
    print(f"[*] Sampling {sample_size:,} URLs (random_state={random_seed})...")
    sample_df = full_df.sample(n=sample_size, random_state=random_seed).reset_index(drop=True)

    success_count = 0
    failure_count = 0
    failures_info = []
    
    extracted_records = []

    print("[*] Extracting features for sampled URLs...")
    for idx, row in sample_df.iterrows():
        raw_url = row['URL']
        target_label = row['label']
        
        try:
            feats = extract_url_features(raw_url)
            
            # Sanity checks
            if not isinstance(feats, dict):
                raise ValueError("Output is not a dictionary")
                
            missing_keys = set(EXPECTED_FEATURES) - set(feats.keys())
            if missing_keys:
                raise ValueError(f"Missing expected keys: {missing_keys}")
                
            # Check NaN or Inf values
            for k, v in feats.items():
                if v is None or (isinstance(v, float) and (np.isnan(v) or np.isinf(v))):
                    raise ValueError(f"Feature '{k}' contains invalid value: {v}")
                    
                if k in BINARY_FEATURES and v not in (0, 1):
                    raise ValueError(f"Binary feature '{k}' contains non-binary value: {v}")

            feats['label'] = int(target_label)
            extracted_records.append(feats)
            success_count += 1

        except Exception as e:
            failure_count += 1
            failures_info.append({"index": idx, "url": raw_url, "error": str(e)})

    failure_pct = (failure_count / sample_size) * 100
    print(f"\n1. EXTRACTION STABILITY VERIFICATION:")
    print(f"   - Total Sampled URLs:   {sample_size:,}")
    print(f"   - Successfully Processed: {success_count:,}")
    print(f"   - Failures / Exceptions: {failure_count}")
    print(f"   - Failure Rate:          {failure_pct:.4f}%")
    print(f"   - Validation Status:     {'PASSED' if failure_count == 0 else 'FAILED'}\n")

    # Create extracted features DataFrame
    ext_df = pd.DataFrame(extracted_records)
    
    legit_df = ext_df[ext_df['label'] == 1]
    phish_df = ext_df[ext_df['label'] == 0]

    report_rows = []
    
    print(f"2. FEATURE COMPARISON BETWEEN CLASSES (Legitimate vs Phishing):")
    print(f"   {'Feature':<25} | {'Legit Mean':<10} | {'Phish Mean':<10} | {'Legit Std':<10} | {'Phish Std':<10} | {'Legit %1':<8} | {'Phish %1':<8}")
    print("-" * 95)

    for feat in EXPECTED_FEATURES:
        l_series = legit_df[feat]
        p_series = phish_df[feat]
        
        l_mean = float(l_series.mean())
        p_mean = float(p_series.mean())
        l_std = float(l_series.std())
        p_std = float(p_series.std())
        l_min = float(l_series.min())
        p_min = float(p_series.min())
        l_max = float(l_series.max())
        p_max = float(p_series.max())

        is_binary = feat in BINARY_FEATURES
        l_pct_ones = float((l_series == 1).mean() * 100) if is_binary else None
        p_pct_ones = float((p_series == 1).mean() * 100) if is_binary else None

        row_data = {
            "feature": feat,
            "is_binary": is_binary,
            "legit_mean": round(l_mean, 4),
            "phish_mean": round(p_mean, 4),
            "mean_diff": round(abs(l_mean - p_mean), 4),
            "legit_std": round(l_std, 4),
            "phish_std": round(p_std, 4),
            "legit_min": round(l_min, 4),
            "phish_min": round(p_min, 4),
            "legit_max": round(l_max, 4),
            "phish_max": round(p_max, 4),
            "legit_pct_ones": round(l_pct_ones, 2) if l_pct_ones is not None else "",
            "phish_pct_ones": round(p_pct_ones, 2) if p_pct_ones is not None else ""
        }
        report_rows.append(row_data)

        l_pct_str = f"{l_pct_ones:.1f}%" if l_pct_ones is not None else "N/A"
        p_pct_str = f"{p_pct_ones:.1f}%" if p_pct_ones is not None else "N/A"
        
        print(f"   {feat:<25} | {l_mean:<10.4f} | {p_mean:<10.4f} | {l_std:<10.4f} | {p_std:<10.4f} | {l_pct_str:<8} | {p_pct_str:<8}")

    print()

    # Save validation CSV report
    report_df = pd.DataFrame(report_rows)
    report_df.to_csv(REPORT_CSV_PATH, index=False)
    print(f"[+] Saved validation report to {REPORT_CSV_PATH}")

    # Save summary JSON
    summary_data = {
        "sample_size": sample_size,
        "success_count": success_count,
        "failure_count": failure_count,
        "failure_pct": failure_pct,
        "validation_passed": (failure_count == 0),
        "legitimate_sample_count": len(legit_df),
        "phishing_sample_count": len(phish_df),
        "feature_metrics": report_rows
    }
    with open(SUMMARY_JSON_PATH, 'w') as f:
        json.dump(summary_data, f, indent=2)
    print(f"[+] Saved validation summary JSON to {SUMMARY_JSON_PATH}")

    return summary_data

if __name__ == '__main__':
    run_validation()
