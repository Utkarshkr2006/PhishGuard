# Contributing to PhishGuard

Thank you for your interest in contributing to PhishGuard!

This document explains how to get set up, run the tests, and submit changes.

---

## Table of Contents

1. [Getting Started](#1-getting-started)
2. [Project Structure](#2-project-structure)
3. [Running Tests](#3-running-tests)
4. [Contribution Guidelines](#4-contribution-guidelines)
5. [Architecture Constraints](#5-architecture-constraints)
6. [Issue Reporting](#6-issue-reporting)

---

## 1. Getting Started

### Prerequisites
- Python 3.10+
- Git

### Setup

```bash
git clone https://github.com/your-username/PhishGuard.git
cd PhishGuard

# Create a virtual environment
python -m venv venv

# Activate (Windows PowerShell)
.\venv\Scripts\Activate.ps1

# Activate (Linux / macOS)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

> **Note:** Model `.pkl` files and the full dataset CSV are excluded from the repository due to size constraints.
> You must re-train models locally before testing:
> ```bash
> python model/train_models.py
> ```
> This requires `data/PhiUSIIL_Phishing_URL_Dataset.csv`.
> Download it from the [UCI ML Repository (Dataset ID 967)](https://archive.ics.uci.edu/dataset/967).

---

## 2. Project Structure

```
PhishGuard/
├── app.py                   # Flask application entry point
├── analysis/
│   ├── url_features.py      # URL lexical feature extractor (23 features)
│   ├── predictor.py         # Random Forest inference wrapper
│   ├── explainability.py    # Deterministic rule-based explanation engine
│   ├── risk_scoring.py      # Heuristic risk scoring engine (0–100 scale)
│   └── test_*.py            # Subsystem unit test scripts
├── model/
│   ├── train_models.py      # Model training script
│   └── feature_names.json   # Runtime feature column config (tracked)
├── templates/
│   ├── index.html           # Homepage template
│   └── result.html          # Analysis result template
├── static/
│   ├── css/style.css        # Dark-mode custom stylesheet
│   └── js/main.js           # Minimal frontend interaction script
├── tests/
│   └── test_app.py          # Pytest integration & security test suite
├── data/
│   └── evaluation/          # Confusion matrices and evaluation artifacts
├── requirements.txt
├── README.md
├── CONTRIBUTING.md          # This file
└── .gitignore
```

---

## 3. Running Tests

### Full Integration & Security Test Suite
```bash
python -m pytest tests/test_app.py -v
```
Expected: **9 / 9 tests passing**

### Subsystem Unit Tests
```bash
python analysis/test_url_features.py
python analysis/test_predictor.py
python analysis/test_explainability.py
python analysis/test_risk_scoring.py
python data/validate_phase8.py
```

---

## 4. Contribution Guidelines

### Commit Style
Use clear, descriptive commit messages:
```
fix: correct URL length validation boundary
feat: add entropy normalization for path feature
docs: expand README with dataset download instructions
test: add edge case for empty path URL
```

### Code Style
- Follow standard **PEP 8** formatting.
- All public functions must have docstrings.
- Preserve existing module docstring headers.

### Pull Requests
1. Fork the repository.
2. Create a descriptive feature branch: `git checkout -b feat/your-feature-name`
3. Ensure all 9 integration tests pass before opening a PR.
4. Submit a pull request with a clear description of changes and their justification.

---

## 5. Architecture Constraints

The following constraints are **non-negotiable** for all contributions:

| Constraint | Reason |
|:---|:---|
| **Zero outbound HTTP requests to submitted URLs** | Safety — must never expose analyst to tracking or malicious servers |
| **No DNS resolution of submitted URLs** | Safety — same reason as above |
| **No eval() / exec() / subprocess** | Security hardening |
| **23 lexical feature set is frozen** | Feature changes require full model retraining with documented justification |
| **Jinja2 autoescaping must remain active** | XSS protection |
| **Flask debug mode must remain `False`** | Prevents debugger exposure in production |

Changes that violate any of the above constraints will not be accepted.

---

## 6. Issue Reporting

When reporting a bug or unexpected behavior, please include:

- Python version (`python --version`)
- Operating system
- The URL string that triggered unexpected output (if safe to share — do not share real sensitive URLs)
- Full error output (if any)
- Steps to reproduce

Open issues at: `https://github.com/your-username/PhishGuard/issues`

---

*PhishGuard is developed for the Cybersecurity Awareness Hackathon.*
