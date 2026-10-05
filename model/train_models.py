"""
PhishGuard 2.0 - Baseline Model Training and Evaluation Pipeline
Module: model/train_models.py

Trains and evaluates baseline classifiers (Logistic Regression, Decision Tree, Random Forest)
using ONLY features extracted by analysis/url_features.py directly from raw URLs.
Includes random stratified evaluation and domain-aware leakage evaluation.
"""

import os
import sys
import json
import joblib
import time
from concurrent.futures import ProcessPoolExecutor
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import tldextract

from sklearn.model_selection import train_test_split, GroupShuffleSplit
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

# Add parent directory to sys.path to import analysis.url_features
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)
from analysis.url_features import extract_url_features

DATA_DIR = os.path.join(BASE_DIR, 'data')
MODEL_DIR = os.path.join(BASE_DIR, 'model')
EVAL_DIR = os.path.join(DATA_DIR, 'evaluation')

CSV_PATH = os.path.join(DATA_DIR, 'PhiUSIIL_Phishing_URL_Dataset.csv')

EXPECTED_FEATURES = [
    "url_length", "domain_length", "path_length", "num_dots",
    "num_subdomains", "num_digits", "num_letters", "num_hyphens",
    "num_special_chars", "num_at_symbols", "num_question_marks",
    "num_equals", "num_ampersands", "num_slashes", "is_https",
    "is_domain_ip", "has_suspicious_keywords", "has_url_encoding",
    "has_suspicious_tld", "letter_ratio", "digit_ratio",
    "special_char_ratio", "url_entropy"
]

# Configure offline TLDExtract to avoid any network requests
tld_extractor = tldextract.TLDExtract(suffix_list_urls=())

def extract_single_url(url):
    """Helper function for multiprocessing feature extraction."""
    return extract_url_features(url)

def extract_registered_domain(url):
    """Extracts base registered domain (e.g. example.com) for domain leakage grouping."""
    if not url or not isinstance(url, str):
        return "unknown"
    try:
        ext = tld_extractor(url)
        if ext.registered_domain:
            return ext.registered_domain.lower()
        elif ext.domain:
            return ext.domain.lower()
        return url.lower()
    except Exception:
        return url.lower()

def plot_and_save_confusion_matrix(cm, model_name, file_path):
    """Plot and save confusion matrix heatmap."""
    plt.figure(figsize=(6, 5))
    sns.heatmap(
        cm, annot=True, fmt='d', cmap='Blues',
        xticklabels=['Phishing (0)', 'Legitimate (1)'],
        yticklabels=['Phishing (0)', 'Legitimate (1)']
    )
    plt.title(f'Confusion Matrix - {model_name}')
    plt.xlabel('Predicted Label')
    plt.ylabel('True Label')
    plt.tight_layout()
    plt.savefig(file_path, dpi=300)
    plt.close()

def main():
    print("==========================================================")
    print("     PHISHGUARD 2.0 - BASELINE MODEL TRAINING & EVAL")
    print("==========================================================\n")

    os.makedirs(MODEL_DIR, exist_ok=True)
    os.makedirs(EVAL_DIR, exist_ok=True)

    # 1. Load Dataset
    print(f"[*] Loading dataset from {CSV_PATH}...")
    start_time = time.time()
    df = pd.read_csv(CSV_PATH)
    print(f"[+] Loaded {len(df):,} rows in {time.time() - start_time:.2f} seconds.")

    # 2. Extract Features using analysis/url_features.py
    print("[*] Extracting 23 URL features in parallel...")
    urls = df['URL'].tolist()
    labels = df['label'].values

    start_extract = time.time()
    # Use ProcessPoolExecutor for fast parallel feature extraction
    with ProcessPoolExecutor() as executor:
        extracted_features = list(executor.map(extract_single_url, urls, chunksize=2000))
    print(f"[+] Feature extraction completed in {time.time() - start_extract:.2f} seconds.")

    # Convert to DataFrame
    X_df = pd.DataFrame(extracted_features)
    
    # 3. Verify Feature Order and Quality
    assert list(X_df.columns) == EXPECTED_FEATURES, "Extracted feature order mismatch!"
    assert not X_df.isna().any().any(), "Found NaN values in extracted feature matrix!"
    assert not np.isinf(X_df.values).any(), "Found Inf values in extracted feature matrix!"

    X = X_df.values
    y = labels

    print(f"[+] Feature Matrix X shape: {X.shape}")
    print(f"[+] Target Vector y shape:   {y.shape}")

    # Save feature names order for inference reference
    feature_names_path = os.path.join(MODEL_DIR, 'feature_names.json')
    with open(feature_names_path, 'w') as f:
        json.dump(EXPECTED_FEATURES, f, indent=2)
    print(f"[+] Feature names saved to {feature_names_path}")

    # 4. Stratified 80/20 Train-Test Split
    print("\n[*] Performing 80/20 Stratified Train-Test Split (random_state=42)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"   - Training set size: {len(X_train):,}")
    print(f"   - Testing set size:  {len(X_test):,}")

    # Models definition
    models = {
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
        "Decision Tree": DecisionTreeClassifier(random_state=42),
        "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    }

    comparison_results = []
    rf_model_obj = None

    print("\n==========================================================")
    print("           BASELINE MODEL EVALUATION (RANDOM SPLIT)")
    print("==========================================================")

    for name, model in models.items():
        print(f"\n[*] Training {name}...")
        t0 = time.time()
        model.fit(X_train, y_train)
        train_time = time.time() - t0

        y_pred = model.predict(X_test)

        # Overall & Class-Specific Metrics
        acc = accuracy_score(y_test, y_pred)
        
        # Phishing Class (0) Metrics
        prec_phish = precision_score(y_test, y_pred, pos_label=0)
        rec_phish = recall_score(y_test, y_pred, pos_label=0)
        f1_phish = f1_score(y_test, y_pred, pos_label=0)

        # Legitimate Class (1) Metrics
        prec_legit = precision_score(y_test, y_pred, pos_label=1)
        rec_legit = recall_score(y_test, y_pred, pos_label=1)
        f1_legit = f1_score(y_test, y_pred, pos_label=1)

        # Macro Metrics
        macro_prec = precision_score(y_test, y_pred, average='macro')
        macro_rec = recall_score(y_test, y_pred, average='macro')
        macro_f1 = f1_score(y_test, y_pred, average='macro')

        cm = confusion_matrix(y_test, y_pred)

        print(f"   - Accuracy:       {acc * 100:.2f}%")
        print(f"   - Phishing (0) -> Precision: {prec_phish:.4f} | Recall: {rec_phish:.4f} | F1: {f1_phish:.4f}")
        print(f"   - Legit (1)    -> Precision: {prec_legit:.4f} | Recall: {rec_legit:.4f} | F1: {f1_legit:.4f}")
        print(f"   - Macro F1:       {macro_f1:.4f}")
        print(f"   - Confusion Matrix:\n{cm}")

        # Save model pickle
        clean_filename = name.lower().replace(' ', '_') + '.pkl'
        model_save_path = os.path.join(MODEL_DIR, clean_filename)
        joblib.dump(model, model_save_path)
        print(f"   [+] Model saved to {model_save_path}")

        # Plot & save confusion matrix image
        cm_img_path = os.path.join(EVAL_DIR, f"confusion_matrix_{name.lower().replace(' ', '_')}.png")
        plot_and_save_confusion_matrix(cm, name, cm_img_path)

        comparison_results.append({
            "Model": name,
            "Accuracy": round(acc, 4),
            "Phishing_Precision": round(prec_phish, 4),
            "Phishing_Recall": round(rec_phish, 4),
            "Phishing_F1": round(f1_phish, 4),
            "Legit_Precision": round(prec_legit, 4),
            "Legit_Recall": round(rec_legit, 4),
            "Legit_F1": round(f1_legit, 4),
            "Macro_F1": round(macro_f1, 4),
            "TN_Phishing_Correct": int(cm[0, 0]),
            "FP_Phishing_as_Legit": int(cm[0, 1]),
            "FN_Legit_as_Phishing": int(cm[1, 0]),
            "TP_Legit_Correct": int(cm[1, 1])
        })

        if name == "Random Forest":
            rf_model_obj = model

    # Save comparison CSV
    comp_df = pd.DataFrame(comparison_results)
    comp_csv_path = os.path.join(DATA_DIR, 'model_comparison.csv')
    comp_df.to_csv(comp_csv_path, index=False)
    print(f"\n[+] Saved model comparison table to {comp_csv_path}")

    # 5. Random Forest Feature Importance
    if rf_model_obj is not None:
        importances = rf_model_obj.feature_importances_
        feat_imp_df = pd.DataFrame({
            "Feature": EXPECTED_FEATURES,
            "Importance": importances
        }).sort_values(by="Importance", ascending=False).reset_index(drop=True)

        rf_imp_path = os.path.join(DATA_DIR, 'random_forest_feature_importance.csv')
        feat_imp_df.to_csv(rf_imp_path, index=False)
        print(f"[+] Saved Random Forest feature importances to {rf_imp_path}")
        print("\n[*] Top 10 Features (Random Forest):")
        for i, row in feat_imp_df.head(10).iterrows():
            print(f"   {i+1:2d}. {row['Feature']:<25} : {row['Importance']:.4f}")

    # 6. Domain-Aware Evaluation (Investigating Domain Leakage)
    print("\n==========================================================")
    print("      DOMAIN-AWARE EVALUATION (INVESTIGATING LEAKAGE)")
    print("==========================================================")
    print("[*] Extracting registered domains for group-based split...")

    domains = [extract_registered_domain(u) for u in urls]
    domains_arr = np.array(domains)
    unique_domains = len(set(domains))
    print(f"[+] Extracted {unique_domains:,} unique registered domains across {len(df):,} URLs.")

    gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
    train_idx, test_idx = next(gss.split(X, y, groups=domains_arr))

    X_train_dom, X_test_dom = X[train_idx], X[test_idx]
    y_train_dom, y_test_dom = y[train_idx], y[test_idx]
    train_dom_set = set(domains_arr[train_idx])
    test_dom_set = set(domains_arr[test_idx])
    overlap = train_dom_set.intersection(test_dom_set)

    print(f"   - Train set size:  {len(X_train_dom):,} URLs ({len(train_dom_set):,} unique domains)")
    print(f"   - Test set size:   {len(X_test_dom):,} URLs ({len(test_dom_set):,} unique domains)")
    print(f"   - Domain Overlap between Train & Test: {len(overlap)} (Strict 0 overlap achieved)")

    print("\n[*] Retraining Random Forest on Domain-Aware split...")
    rf_domain_model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf_domain_model.fit(X_train_dom, y_train_dom)

    y_pred_dom = rf_domain_model.predict(X_test_dom)

    dom_acc = accuracy_score(y_test_dom, y_pred_dom)
    dom_prec_phish = precision_score(y_test_dom, y_pred_dom, pos_label=0)
    dom_rec_phish = recall_score(y_test_dom, y_pred_dom, pos_label=0)
    dom_f1_phish = f1_score(y_test_dom, y_pred_dom, pos_label=0)
    
    dom_prec_legit = precision_score(y_test_dom, y_pred_dom, pos_label=1)
    dom_rec_legit = recall_score(y_test_dom, y_pred_dom, pos_label=1)
    dom_f1_legit = f1_score(y_test_dom, y_pred_dom, pos_label=1)

    dom_macro_f1 = f1_score(y_test_dom, y_pred_dom, average='macro')
    dom_cm = confusion_matrix(y_test_dom, y_pred_dom)

    print(f"\n   - Domain-Aware Accuracy:       {dom_acc * 100:.2f}%")
    print(f"   - Phishing (0) -> Precision: {dom_prec_phish:.4f} | Recall: {dom_rec_phish:.4f} | F1: {dom_f1_phish:.4f}")
    print(f"   - Legit (1)    -> Precision: {dom_prec_legit:.4f} | Recall: {dom_rec_legit:.4f} | F1: {dom_f1_legit:.4f}")
    print(f"   - Domain-Aware Macro F1:       {dom_macro_f1:.4f}")
    print(f"   - Confusion Matrix:\n{dom_cm}")

    # Plot and save domain-aware confusion matrix
    dom_cm_img_path = os.path.join(EVAL_DIR, 'confusion_matrix_random_forest_domain_aware.png')
    plot_and_save_confusion_matrix(dom_cm, "Random Forest (Domain-Aware Split)", dom_cm_img_path)

    domain_eval_summary = {
        "dataset_total_urls": len(df),
        "unique_domains": unique_domains,
        "train_url_count": len(X_train_dom),
        "test_url_count": len(X_test_dom),
        "train_domain_count": len(train_dom_set),
        "test_domain_count": len(test_dom_set),
        "domain_overlap": len(overlap),
        "metrics": {
            "accuracy": round(float(dom_acc), 4),
            "macro_f1": round(float(dom_macro_f1), 4),
            "phishing_class_0": {
                "precision": round(float(dom_prec_phish), 4),
                "recall": round(float(dom_rec_phish), 4),
                "f1_score": round(float(dom_f1_phish), 4)
            },
            "legitimate_class_1": {
                "precision": round(float(dom_prec_legit), 4),
                "recall": round(float(dom_rec_legit), 4),
                "f1_score": round(float(dom_f1_legit), 4)
            },
            "confusion_matrix": {
                "tn": int(dom_cm[0, 0]),
                "fp": int(dom_cm[0, 1]),
                "fn": int(dom_cm[1, 0]),
                "tp": int(dom_cm[1, 1])
            }
        }
    }

    dom_json_path = os.path.join(DATA_DIR, 'domain_aware_evaluation.json')
    with open(dom_json_path, 'w') as f:
        json.dump(domain_eval_summary, f, indent=2)
    print(f"\n[+] Saved domain-aware evaluation JSON to {dom_json_path}")

    print("\n==========================================================")
    print("                 PHASE 4 COMPLETED SUCCESSFULLY")
    print("==========================================================")

if __name__ == '__main__':
    main()
