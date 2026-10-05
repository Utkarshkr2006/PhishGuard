# PhishGuard 2.0 — Phase 7 Comprehensive Evaluation Report

**Project:** PhishGuard 2.0 — Explainable Phishing Detection Platform  
**Evaluation Phase:** Phase 7  
**Dataset:** PhiUSIIL Phishing URL Dataset (UCI ML Repository, ID 967)  
**Total Dataset Size:** 235,795 URLs (134,850 Legitimate / 100,945 Phishing)  
**Evaluation Date:** 2026-10-01  

---

## 1. Model Performance (Random Stratified 80/20 Split)

Three baseline classifiers were trained using **23 lexical URL features** extracted by
`analysis/url_features.py` from raw URL strings. Features were extracted without any
network requests or access to the submitted URLs.

**Training Set:** 188,636 URLs  
**Test Set:** 47,159 URLs  
**Split Strategy:** Stratified 80/20, `random_state=42`

### 1.1 Classifier Comparison Table

| Model | Accuracy | Phishing Precision | Phishing Recall | Phishing F1 | Legit F1 | Macro F1 |
|:---|:---|:---|:---|:---|:---|:---|
| Logistic Regression | 99.39% | 0.9986 | 0.9871 | 0.9928 | 0.9947 | 0.9937 |
| Decision Tree | 99.45% | 0.9959 | 0.9912 | 0.9935 | 0.9952 | 0.9944 |
| **Random Forest** | **99.52%** | **0.9971** | **0.9916** | **0.9943** | **0.9958** | **0.9951** |

### 1.2 Confusion Matrix Summary (Random Forest — Random Split)

| | Predicted Phishing (0) | Predicted Legitimate (1) |
|:---|:---|:---|
| **Actual Phishing (0)** | 20,019 (TN) | 170 (FP) |
| **Actual Legitimate (1)** | 58 (FN) | 26,912 (TP) |

### 1.3 Random Forest Feature Importance (Top 10)

| Rank | Feature | Gini Importance |
|:---|:---|:---|
| 1 | `is_https` | 0.4097 (40.97%) |
| 2 | `path_length` | 0.1623 (16.23%) |
| 3 | `num_slashes` | 0.1361 (13.61%) |
| 4 | `num_digits` | 0.0561 (5.61%) |
| 5 | `num_special_chars` | 0.0544 (5.44%) |
| 6 | `digit_ratio` | 0.0474 (4.74%) |
| 7 | `url_entropy` | 0.0226 (2.26%) |
| 8 | `has_suspicious_tld` | 0.0194 (1.94%) |
| 9 | `num_subdomains` | 0.0183 (1.83%) |
| 10 | `url_length` | 0.0174 (1.74%) |

> [!NOTE]
> The heavy reliance on `is_https` (40.97%) reflects a dataset characteristic where 100% of
> legitimate training samples used HTTPS. This does not represent real-world universality.

---

## 2. Domain-Aware Evaluation

To investigate potential domain leakage in the stratified random split, a **group-based split**
was performed using registered domain names extracted via `tldextract`.

| Split Property | Value |
|:---|:---|
| Total Unique Registered Domains | 175,509 |
| Training URLs | 193,843 |
| Training Unique Domains | 140,407 |
| Test URLs | 41,952 |
| Test Unique Domains | 35,102 |
| **Domain Overlap (Train ∩ Test)** | **0** |

> The domain-aware split is **not** an exact 80/20 — `GroupShuffleSplit` targets approximately
> 80/20 by group membership, not by individual URL count. The resulting split was ~82/18 by URL count.

### Domain-Aware Random Forest Metrics

| Metric | Value |
|:---|:---|
| Accuracy | **99.54%** |
| Macro F1 | **0.9950** |
| Phishing Precision | 0.9962 |
| Phishing Recall | 0.9909 |
| Phishing F1 | 0.9936 |
| Legitimate Precision | 0.9950 |
| Legitimate Recall | 0.9979 |
| Legitimate F1 | 0.9964 |

**Comparison with random split:** Performance is virtually identical (within ±0.001 F1).
The negligible difference confirms that the model's strong performance reflects **generalizable
lexical pattern learning** rather than domain memorization.

**Why domain-aware evaluation matters:** In phishing URL detection, the same legitimate domain
(e.g., `google.com`) may appear thousands of times in training data. A naive random split would
allow the model to "memorize" associations with specific domains, inflating test accuracy.
Domain-aware grouping ensures the test set exclusively contains domains not seen during training,
more closely simulating real-world deployment against novel URLs.

---

## 3. Realistic URL Sanity Check

The sanity check evaluated `predict_url()` on 13 URL categories using the trained Random Forest.

### 3.1 Results Summary

| Category | URL | RF Phish Prob | Observation |
|:---|:---|:---|:---|
| Benign | `https://www.wikipedia.org` | 0.0028 | Low probability, Legitimate prediction |
| Benign | `https://accounts.google.com` | 0.0000 | Zero probability, Legitimate prediction |
| Benign | `https://www.amazon.in` | 0.0025 | Low probability, Legitimate prediction |
| Benign | `https://github.com/login` | **1.0000** | Saturated — **dataset artifact** |
| Benign | `https://example.com/products?id=12345` | **1.0000** | Saturated — **dataset artifact** |
| Benign | `http://example.com` | **1.0000** | Saturated — **dataset artifact** |
| Moderately Suspicious | `https://example.com/login/verify` | 1.0000 | Contains keyword, path depth |
| Obviously Suspicious | `http://secure-login-verify-account.bank-update.xyz/...` | 1.0000 | Multiple indicators |
| Obviously Suspicious | `http://192.168.1.100/admin/login` | 1.0000 | IP domain, HTTP |
| Obviously Suspicious | `http://admin:secret@phishing-target.com/account` | 1.0000 | @ symbol |

**Aggregate Statistics:**
- Min Phishing Probability: 0.0000
- Max Phishing Probability: 1.0000
- Predictions with Phishing Prob == 0.0: 1/13 (7.7%)
- Predictions with Phishing Prob == 1.0: 10/13 (76.9%)

### 3.2 Documented False-Positive Cases and Dataset Artifact Explanation

The following URLs received saturated phishing probability (`1.0`) from the Random Forest
despite being structurally legitimate:

- **`https://github.com/login`** — The `/login` path depth combined with the keyword `login`
  maps to patterns learned as phishing in training data. In the PhiUSIIL dataset, legitimate
  samples were predominantly bare root-domain URLs (e.g., `https://domain.com`).
- **`https://example.com/products?id=12345`** — Deep path + numeric ID query string triggers
  learned path/digit patterns associated with phishing.
- **`http://example.com`** — HTTP protocol alone places this into phishing-associated territory
  due to the 100% HTTPS adoption in legitimate training samples.

> **IMPORTANT:** These saturated probabilities demonstrate **training dataset distribution
> artifacts**, not evidence that these URLs are malicious. The PhishGuard risk scoring engine
> accounts for this by treating the RF model as one supporting signal (+15 points only).

---

## 4. Explainability Evaluation

Module: `analysis/explainability.py`

### 4.1 Assessment

| Property | Status |
|:---|:---|
| Deterministic output (identical URLs produce identical explanations) | Verified |
| Indicators correspond to actual extracted feature values | Verified — each indicator checks a specific feature condition |
| No invented or hallucinated indicators | Verified — indicators only fire when conditions are met |
| Language avoids certainty claims | Verified — uses "indicator detected", "may indicate", "signal detected" |
| HTTPS correctly labeled (not marked as "safe") | Verified — labeled "Uses encrypted HTTPS connection protocol" |
| Positive signals shown for clean URLs | Verified — `https://www.wikipedia.org` shows 2 positive signals |

### 4.2 Known Explainability Limitation

Legitimate login or account-management URLs that contain words such as `login`, `account`,
`verify`, `secure` will trigger the `has_suspicious_keywords` indicator. This is an inherent
limitation of keyword-based lexical analysis without domain context.

**Example observed:** `https://accounts.google.com` and `https://github.com/login` both
trigger *"Suspicious account/login-related keyword indicator detected"*, which is technically
correct at the lexical level but contextually misleading for globally trusted domains.

---

## 5. Risk Scoring Evaluation

Module: `analysis/risk_scoring.py`

### 5.1 Verification Results

| Check | Result |
|:---|:---|
| Score bounds (0–100 integers) | **PASSED** |
| Threshold mapping (LOW/MEDIUM/HIGH/CRITICAL) | **PASSED** |
| Deterministic output (same input → same score) | **PASSED** |
| `github.com/login` avoids HIGH/CRITICAL | **PASSED** — Score: 30/100 (MEDIUM) |
| `accounts.google.com` avoids HIGH/CRITICAL | **PASSED** — Score: 15/100 (LOW) |
| Obviously suspicious URLs receive elevated risk | **PASSED** — Scores: 80–100/100 (CRITICAL) |

### 5.2 Risk Level Distribution Across Test URLs

| URL | Risk Score | Risk Level |
|:---|:---|:---|
| `https://www.wikipedia.org` | **0/100** | LOW |
| `https://accounts.google.com` | **15/100** | LOW |
| `https://github.com/login` | **30/100** | MEDIUM |
| `https://example.com/login/verify` | **30/100** | MEDIUM |
| `http://example.com` | **30/100** | MEDIUM |
| `http://admin:secret@phishing-target.com/account` | **80/100** | CRITICAL |
| `http://secure-login-verify-account.bank-update.xyz/...` | **100/100** | CRITICAL |
| `http://192.168.1.100/admin/login` | **100/100** | CRITICAL |

---

## 6. Flask Integration Evaluation

### 6.1 Integration Test Results

```
============================= test session starts =============================
tests/test_app.py::test_home_page_get                 PASSED
tests/test_app.py::test_analyze_benign_url            PASSED
tests/test_app.py::test_analyze_suspicious_url        PASSED
tests/test_app.py::test_analyze_empty_url             PASSED
tests/test_app.py::test_analyze_whitespace_url        PASSED
tests/test_app.py::test_analyze_excessive_length_url  PASSED

6 passed in 3.42s
```

### 6.2 Routes Verified

| Route | Method | Status |
|:---|:---|:---|
| `/` | `GET` | Renders homepage — 200 OK |
| `/analyze` | `POST` | Runs pipeline — 200 OK |
| `/analyze` (empty URL) | `POST` | Returns 400 + validation message |
| `/analyze` (whitespace URL) | `POST` | Returns 400 + validation message |
| `/analyze` (>2048 chars) | `POST` | Returns 400 + validation message |

---

## 7. Security Review

The following security properties were verified by inspecting `app.py`, `analysis/predictor.py`,
`analysis/url_features.py`, and both HTML templates.

| Security Property | Observation |
|:---|:---|
| Network requests to submitted URL | **Not observed** in the reviewed application code path. Analysis operates on URL string only. |
| `requests.get` / `requests.post` usage | **Not found** in any route handler or analysis module. |
| `subprocess` execution on user input | **Not found** in the application. |
| DNS resolution of submitted URL | **Not observed** — `urllib.parse` used for string-only parsing. |
| `eval()` / `exec()` on user input | **Not found** in any application module. |
| Jinja2 autoescaping | **Active** — Flask's default Jinja2 environment escapes all `{{ variable }}` output. No `| safe` filters used on user-supplied content. No `Markup()` wrappers found. |
| Stack-trace exposure to users | **Not observed** — exceptions are caught, logged server-side, and a generic user-facing message is returned. |
| Submitted URL rendered in HTML | Rendered via `{{ url }}` in Jinja2, which applies HTML entity escaping automatically. |

> [!NOTE]
> This review covers the application source code visible in the repository. It does not constitute
> a full penetration test or security audit. The application runs in `debug=True` mode which should
> be disabled before any public-facing deployment.

---

## 8. End-to-End Test Matrix

Generated from the existing pipeline on 2026-10-01.

| URL | Model Prediction | RF Phish Prob | Risk Score | Risk Level |
|:---|:---|:---|:---|:---|
| `https://www.wikipedia.org` | Legitimate | 0.0028 | **0** | LOW |
| `https://accounts.google.com` | Legitimate | 0.0000 | **15** | LOW |
| `https://github.com/login` | Phishing | 1.0000 | **30** | MEDIUM |
| `https://example.com/products?id=12345` | Phishing | 1.0000 | **30** | MEDIUM |
| `http://example.com` | Phishing | 1.0000 | **30** | MEDIUM |
| `https://example.com/login/verify` | Phishing | 1.0000 | **30** | MEDIUM |
| `http://secure-login-verify-account.bank-update.xyz/login.php?...` | Phishing | 1.0000 | **100** | CRITICAL |
| `http://192.168.1.100/admin/login` | Phishing | 1.0000 | **100** | CRITICAL |
| `http://admin:secret@phishing-target.com/account` | Phishing | 1.0000 | **80** | CRITICAL |

> The divergence between RF prediction (Phishing, 1.0) and Risk Score (30/100, MEDIUM) for
> `github.com/login` demonstrates the value of the heuristic risk scoring layer in
> moderating saturated model outputs.

---

## 9. Known Limitations

See [data/phase7_limitations.md](phase7_limitations.md) for the full, evidence-based limitations register.

**Summary of key limitations:**

1. `is_https` feature dominance due to dataset bias (40.97% importance)
2. Random Forest produces saturated binary probabilities — not calibrated real-world probabilities
3. URL-only analysis — no webpage content, DOM, or JavaScript inspection
4. 28 content-dependent dataset features intentionally excluded (require live page retrieval)
5. No DNS resolution, domain-age, WHOIS, or domain reputation analysis
6. No connection to external threat-intelligence feeds or phishing blacklists
7. Moderate false-positive risk on legitimate URLs containing login/account keywords in paths
8. Potential false negatives for lexically clean but genuinely malicious URLs
9. Risk score (0–100) is a heuristic composite — not a statistically calibrated probability
10. No multi-session behavioral profiling or domain reputation history

---

## 10. Conclusion

PhishGuard 2.0 Phase 7 evaluation demonstrates a functioning end-to-end cybersecurity awareness
platform that combines machine learning prediction with deterministic rule-based explainability
and heuristic risk scoring.

**What the system achieves:**

- Three baseline classifiers trained on 23 lexical URL features achieve **99.39%–99.52% accuracy**
  on a stratified hold-out test set from the PhiUSIIL dataset.
- Domain-aware evaluation with zero domain overlap between train and test sets confirms
  performance (**99.54% accuracy, Macro F1: 0.9950**) does not rely on domain memorization.
- The explainability engine generates deterministic, evidence-backed indicators without invented
  or hallucinated reasons.
- The heuristic risk scoring engine prevents saturated model probabilities from directly driving
  user-facing risk classification — `github.com/login` receives MEDIUM (30/100) rather than
  CRITICAL, while `http://192.168.1.100/admin/login` correctly receives CRITICAL (100/100).
- All 6 Flask integration tests pass, and no direct URL network requests were observed in the
  application path.

**What the system does NOT claim:**

- PhishGuard does not guarantee detection of all phishing URLs.
- Random Forest probabilities are not calibrated real-world phishing probabilities.
- The risk score (0–100) is a heuristic indicator, not a statistical confidence value.
- The system's URL-only analysis is fundamentally bounded — it cannot inspect webpage content,
  check domain reputation, or benefit from external threat-intelligence feeds in its current form.
- Dataset-level performance (99.5% accuracy) should not be interpreted as real-world deployment
  performance without broader evaluation across diverse URL populations.

*This evaluation was produced as part of the PhishGuard 2.0 hackathon development process.
All results are reproducible using the scripts and artifacts in the project repository.*
