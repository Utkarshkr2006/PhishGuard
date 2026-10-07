# PhishGuard

> **Transparent, Explainable Phishing URL Analysis Platform**  
> *Offline lexical threat analysis powered by Machine Learning, deterministic rule-based explainability, and heuristic risk scoring.*

[![Tests](https://img.shields.io/badge/Tests-9%20Passed-success.svg)](#13-running-tests)
[![Status](https://img.shields.io/badge/Validation-Pass%20with%20Limitations-yellow.svg)](#17-project-status)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Flask-3.0%2B-lightgrey.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 1. Overview

**PhishGuard** is an explainable cybersecurity web application designed to evaluate suspicious URLs without visiting or downloading target websites. By analyzing the structural, syntactic, and lexical characteristics of a submitted web address, PhishGuard provides actionable security assessments and transparent evidence indicators.

> [!IMPORTANT]
> **What PhishGuard Does NOT Claim:**  
> PhishGuard does not claim to detect 100% of phishing attacks. Analysis is performed strictly offline on the URL string itself. PhishGuard does not connect to the remote host, inspect web page contents, or verify domain reputation in external blacklists.

---

## 2. Problem Statement

Phishing remains one of the most pervasive cyber threat vectors, tricking users into revealing credentials, payment details, or personal data. Modern users face two critical problems when encountering suspicious links:

1. **Opaque "Black-Box" Decisions:** Traditional security scanners often output a binary "safe/unsafe" label without explaining *why*, leaving users unable to learn or assess context.
2. **Safety Risks of Active Scanning:** Conventional security tools frequently fetch or crawl the target URL, potentially exposing the user's IP address, triggering tracking beacons, or executing malicious server-side scripts.

Users need an immediate, safe, and transparent tool that breaks down the structural warning signs of a URL into plain-language indicators.

---

## 3. Solution & Pipeline Architecture

PhishGuard solves this problem by using a **100% offline, multi-tier inspection pipeline**:

```
                    User Submitted URL
                            │
                            ▼
               [Flask Route /analyze (Input Validation)]
                            │
                            ▼
           [URL Feature Extractor (23 Lexical Features)]
                            │
            ┌───────────────┴───────────────┐
            ▼                               ▼
 [Random Forest Classifier]     [Rule-Based Explainability]
   (Model Phishing Signal)        (Deterministic Indicators)
            │                               │
            └───────────────┬───────────────┘
                            ▼
               [Heuristic Risk Scoring Engine]
                  (0–100 Scale & Risk Level)
                            │
                            ▼
              [Rendered Results Dashboard]
        (Score, Indicators, Recommendations, ML Signal)
```

---

## 4. Key Features

- **100% Offline URL Analysis:** Zero outbound HTTP requests, zero DNS resolutions, zero target server interactions.
- **23 Deterministic Lexical Features:** Extracts entropy, length ratios, digit/special character densities, suspicious keywords, and TLD indicators directly from the raw string.
- **Random Forest phishing URL classifier:** trained on 188,636 URLs from the PhiUSIIL benchmark dataset.
- **Rule-Based Explainability Engine:** Generates deterministic, evidence-backed security explanations tied directly to extracted feature values.
- **Heuristic Risk Scoring:** Synthesizes ML signals, structural red flags, and compound indicators into an intuitive 0–100 score.
- **Clear Risk Tiers:** Categorizes URLs into `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL` risk tiers with tailored security recommendations.
- **Input Validation & Security Hardening:** Rejects malformed or oversized payloads (>2048 characters), enforces Jinja2 autoescaping against XSS, and prevents stack trace leakage.
- **Demo Quick-Select:** 1-click test pills on the homepage allow rapid testing of Benign, Borderline, and Critical URL samples.

---

## 5. Technology Stack

- **Backend:** Python 3.10+, Flask 3.0+
- **Machine Learning & Data Science:** scikit-learn, joblib, pandas, numpy
- **Evaluation & Domain Handling:** tldextract, matplotlib, seaborn
- **Testing:** pytest 8.0+
- **Frontend:** HTML5, Vanilla CSS3 (Custom dark-mode cyber design, no heavy frameworks)
- **Deployment:** WSGI-compatible, local-first architecture

---

## Demo

Screenshots will be added in the final presentation/demo update.

### URL Analysis Dashboard

A screenshot of the PhishGuard URL analysis interface.

### Risk Assessment

A screenshot showing the model signal, heuristic risk score, indicators, and recommendations.

---

## 6. Dataset

PhishGuard was trained and benchmarked on the **PhiUSIIL Phishing URL Dataset** (UCI Machine Learning Repository, Dataset ID: 967).

- **Total Records:** 235,795 URLs
  - **Legitimate:** 134,850 URLs (57.19%)
  - **Phishing:** 100,945 URLs (42.81%)
- **Custom Lexical Representation:** While the raw PhiUSIIL dataset includes 56 columns, **28 of those features are content-dependent** (e.g., `HasPasswordField`, `NoOfiFrame`, `HasSubmitButton`) requiring live webpage fetching. To maintain strict offline safety and zero target contact, PhishGuard deliberately discards all content-dependent columns and extracts **23 pure lexical URL features** directly from raw URL strings.

---

## 7. Machine Learning

Three baseline models were trained using an 80/20 stratified train/test split (188,636 train / 47,159 test) on the 23 lexical features:

| Classifier | Accuracy | Phishing Precision | Phishing Recall | Phishing F1 | Macro F1 |
|:---|:---|:---|:---|:---|:---|
| Logistic Regression | 99.39% | 0.9986 | 0.9871 | 0.9928 | 0.9937 |
| Decision Tree | 99.45% | 0.9959 | 0.9912 | 0.9935 | 0.9944 |
| **Random Forest (Selected)** | **99.52%** | **0.9971** | **0.9916** | **0.9943** | **0.9951** |

### Domain-Aware Evaluation (Zero Domain Leakage)
To guard against domain memorization, a group-based split was evaluated using 175,509 unique registered domains with **zero domain overlap** between train and test sets:
- **Domain-Aware Accuracy:** **99.54%**
- **Domain-Aware Macro F1:** **0.9950**

> [!NOTE]
> High benchmark scores reflect performance on the benchmark dataset distribution. They must not be interpreted as guaranteed real-world deployment accuracy across all internet traffic.

---

## 8. Explainability Engine

PhishGuard’s explainability engine is **deterministic, rule-based, and evidence-backed**:
- Every flagged indicator corresponds to an actual extracted feature value (e.g. `@` symbol count, IP hostname check, digit concentration, suspicious TLD).
- Indicators use cautious language (*"indicator detected"*, *"can obscure destination"*).
- Positive structural indicators (e.g., HTTPS encryption) are highlighted without claiming the destination is guaranteed safe.
- Contextual notices explain that keywords like `login` or `account` are natural on authentic service portals as well as phishing sites.

---

## 9. Heuristic Risk Scoring

The primary metric displayed to users is the **Heuristic Risk Score (0–100)**:

| Score Range | Risk Level | Meaning & Actionable Guidance |
|:---:|:---:|:---|
| **0 – 24** | **LOW** | No major structural anomalies. Continue standard verification before entering credentials. |
| **25 – 49** | **MEDIUM** | Some structural flags detected (e.g. login keyword or uncalibrated model flag). Exercise caution. |
| **50 – 74** | **HIGH** | Multiple suspicious indicators detected. Avoid submitting credentials or sensitive data. |
| **75 – 100** | **CRITICAL** | Multiple strong threat indicators detected. Do not interact. |

> [!WARNING]
> **Heuristic Risk Score vs. Probability:**  
> The 0–100 score is a deterministic heuristic composite based on observable structural rules. It is **not** a calibrated statistical probability (a score of 75/100 does not mean a 75% chance of phishing).

---

## 10. Security Design

- **Zero Network Interaction:** No socket connections, DNS requests, or HTTP requests to submitted URLs.
- **XSS Protection:** Automatic Jinja2 template HTML entity escaping (`{{ url }}`); no unsafe raw rendering.
- **Strict Input Validation:** Empty input rejection, whitespace-only rejection, and 2048-character length boundaries.
- **Hardened Error Handling:** Production mode active (`debug=False`); internal exceptions return a generic HTTP 500 error without exposing stack traces or file paths.
- **Log Sanitization:** Server-side error logs sanitize embedded credentials (`user:pass@`) and truncate URLs to prevent log flooding.

---

## 11. Installation

### Prerequisites
- Python 3.10 or higher
- Git

### Setup Steps
1. **Clone the repository:**
   ```bash
   git clone https://github.com/Utkarshkr2006/PhishGuard.git
   cd PhishGuard
   ```

   > **Note:** The trained Random Forest inference model (`model/random_forest.pkl`) is included in the repository. No retraining is required to run the application after cloning.

2. **Create and activate a virtual environment:**
   - **Windows (PowerShell):**
     ```powershell
     python -m venv venv
     .\venv\Scripts\Activate.ps1
     ```
   - **Linux / macOS:**
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 12. Running the Application

Start the local Flask server:
```bash
python app.py
```

The application will launch locally at:
```
http://127.0.0.1:5000
```
Open this address in any modern web browser to access the PhishGuard URL Threat Inspector.

---

## 13. Running Tests

Run the complete automated integration and security test suite:
```bash
python -m pytest tests/test_app.py -v
```

### Module Verification Scripts
You can also run individual subsystem test scripts:
```bash
# Test URL feature extractor
python analysis/test_url_features.py

# Test Random Forest prediction engine
python analysis/test_predictor.py

# Test explainability rule generator
python analysis/test_explainability.py

# Test heuristic risk scoring engine
python analysis/test_risk_scoring.py

# Run full end-to-end regression validation
python data/validate_phase8.py
```

### Retraining the Model (Developer / Reproducibility)

Retraining is **not required** to run PhishGuard. The trained Random Forest model is included in the repository.

To reproduce model training from scratch:
1. Download the PhiUSIIL dataset from the [UCI ML Repository (Dataset ID: 967)](https://archive.ics.uci.edu/dataset/967) into `data/`.
2. Run the training script:
   ```bash
   python model/train_models.py
   ```

---

## 14. Example Analysis

| Submitted URL | Model Phishing Signal | Heuristic Risk Score | Risk Level | Primary Indicators |
|:---|:---:|:---:|:---:|:---|
| `https://www.wikipedia.org` | Legitimate (0.0028) | **0 / 100** | **LOW** | Encrypted HTTPS protocol, clean root domain structure. |
| `https://accounts.google.com` | Legitimate (0.0000) | **15 / 100** | **LOW** | Account keyword detected, HTTPS connection. |
| `https://github.com/login` | Phishing (1.0000) | **30 / 100** | **MEDIUM** | Login keyword indicator. *(Model saturation tempered by risk rules).* |
| `http://192.168.1.100/admin/login` | Phishing (1.0000) | **100 / 100** | **CRITICAL** | Raw IP domain, HTTP unencrypted, admin/login keywords, high digit density. |
| `http://admin:secret@phishing-target.com/account` | Phishing (1.0000) | **80 / 100** | **CRITICAL** | `@` symbol domain obfuscation, HTTP unencrypted, account keyword. |

---

## 15. Limitations

PhishGuard’s design incorporates specific trade-offs to ensure safety, privacy, and speed:

1. **URL-Only Lexical Analysis:** PhishGuard cannot inspect webpage HTML, JavaScript execution, DOM structures, or rendered forms.
2. **No Webpage / Content Inspection:** Attacks using clean, benign-looking URLs (e.g. Google Docs phishing forms) cannot be caught via lexical inspection alone.
3. **No Live Threat Intelligence:** PhishGuard does not query live commercial blacklists (Google Safe Browsing, PhishTank, VirusTotal).
4. **No DNS / Domain Age Signals:** Newly registered domains cannot be distinguished from established domains without live WHOIS lookups.
5. **Model Probability Saturation:** The trained Random Forest outputs saturated probabilities (`0.0` or `1.0`) on complex paths. Raw model output must not be treated as a calibrated real-world probability.
6. **HTTPS Feature Dominance:** Because 100% of legitimate training samples used HTTPS, the model learned a strong bias toward HTTPS. PhishGuard moderates this via heuristic rules.
7. **False-Positive Potential:** Legitimate deep-path URLs containing authentication keywords (such as `github.com/login`) receive elevated flags.
8. **False-Negative Potential:** Sophisticated attackers using short, clean, HTTPS URLs without obvious keywords may receive a LOW risk assessment.
9. **Heuristic Score Calibration:** The 0–100 score is a deterministic rule-based composite, not a statistically calibrated probability.

---

## 16. Future Improvements

Planned future iterations (not present in current version):
- **Domain Age & WHOIS Integration:** Incorporate domain registration date signals via offline caching.
- **Calibrated Probability Models:** Implement isotonic regression or Platt scaling to output well-calibrated posterior probabilities.
- **Optional Opt-In DOM Inspection:** Provide an optional headless browser sandbox for live DOM analysis.
- **Threat Intelligence Blacklists:** Support optional API integrations (SURBL, OpenPhish) for known-malicious hashes.
- **Browser Extension:** Package lexical analysis into a lightweight client-side browser plugin.

---

## 17. Project Status

- **Automated Tests:** 9 / 9 Integration & Security Tests Passing
- **End-to-End Validation:** 8 / 8 Benchmark URLs Passing
- **Security Audit:** Zero network calls to submitted URLs, debug disabled, XSS-safe
- **Final Validation Status:** **PASS WITH LIMITATIONS**

---

## 18. Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup instructions, architecture constraints, and contribution guidelines.

---

## 19. License

This project is licensed under the [MIT License](LICENSE).

---

*PhishGuard — Developed for the Cybersecurity Awareness Hackathon.*
