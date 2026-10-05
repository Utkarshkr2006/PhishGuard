# PhishGuard 2.0 — Phase 7 Known Limitations

> These limitations are documented based on observed system behavior, architecture constraints,
> and validated experimental results. No limitation is inferred or speculative without supporting evidence.

---

## Limitation 1: Dataset Characteristics Affecting Feature Importance

**Evidence:** Feature importance analysis showed `is_https` accounts for **40.97%** of the
Random Forest's decision weight. Inspection of the PhiUSIIL dataset confirmed that **100%**
of legitimate training samples used HTTPS while only ~48.8% of phishing samples did.

**Effect:** The model has learned a strong association between the absence of HTTPS and phishing.
This creates a risk of false positives for legitimate HTTP-only sites and false negatives for
phishing sites that use HTTPS (free SSL certificates are widely available to attackers).

**Status:** Mitigated in the risk scoring layer — HTTP receives a moderate additive penalty
(+15 points) rather than being treated as definitive proof of phishing.

---

## Limitation 2: Saturated Random Forest Output Probabilities

**Evidence:** The sanity check (Phase 5A) showed 10/13 test URLs received exactly `1.0` phishing
probability from the Random Forest model. URLs such as `https://github.com/login`,
`https://example.com/products?id=12345`, and `http://example.com` all received 100% phishing
probability despite being structurally legitimate.

**Effect:** Raw RF probabilities cannot be used as calibrated real-world risk percentages.
The model outputs reflect learned decision boundaries from the training dataset distribution,
not absolute probability of malicious intent.

**Mitigation Applied:** Raw RF probability is not presented as the primary result in the
PhishGuard UI. It is labeled as *"Model signal (not a calibrated real-world probability)"*.
The composite heuristic Risk Score (0–100) is the primary user-facing metric.

---

## Limitation 3: URL-Only Lexical Analysis

**Scope:** PhishGuard extracts 23 features from the raw URL string only. No webpage HTML,
JavaScript execution, rendered DOM, or server-side content is inspected.

**Effect:** Phishing pages that use clean, short, HTTPS URLs (e.g., free subdomain services
like `my-bank.glitch.me` or Cloudflare Pages) may not trigger lexical indicators and could
receive low risk scores despite being genuinely malicious.

---

## Limitation 4: No Webpage or Content-Dependent Inspection

**Scope:** 28 out of 56 features in the PhiUSIIL dataset are content-dependent
(e.g., `HasSubmitButton`, `HasPasswordField`, `HasExternalFormSubmit`, `NoOfiFrame`).
These were deliberately excluded from PhishGuard's feature set because they require
live webpage retrieval.

**Effect:** Phishing characteristics that are only detectable via DOM inspection (e.g.,
hidden credential harvesting forms, iframe embedding, obfuscated JavaScript redirects) are
invisible to the current system.

---

## Limitation 5: No DNS or Domain Reputation Analysis

**Scope:** PhishGuard performs no DNS resolution, domain age lookup, WHOIS query,
or registrar-based reputation check.

**Effect:** Newly registered phishing domains that use clean structural patterns
(no suspicious TLD, no keywords, HTTPS enabled) cannot be identified as newly created
domains — a common phishing indicator.

---

## Limitation 6: No Threat-Intelligence Feed Integration

**Scope:** PhishGuard is not connected to external phishing blacklists, threat-intelligence
APIs, or reputation databases (PhishTank, VirusTotal, SURBL, Google Safe Browsing, etc.).

**Effect:** Known phishing URLs that have already been confirmed and listed in external
databases are evaluated solely on structural/lexical features. A structurally clean but
previously reported phishing URL would not benefit from blacklist confirmation.

---

## Limitation 7: False Positives on Legitimate Complex URLs

**Evidence:** Observed in sanity checks:
- `https://github.com/login` → RF Phishing Probability: 1.0, Risk Score: 30/100 (MEDIUM)
- `https://accounts.google.com` → Risk Score: 15/100 (LOW) — keyword flag triggered
- `https://example.com/products?id=12345` → RF Phishing Probability: 1.0, Risk Score: 30/100 (MEDIUM)

**Effect:** Legitimate deep-path URLs, especially those containing security-relevant keywords
like `login`, `account`, `verify`, `secure` in path or hostname, can trigger moderate-level
risk indicators. The heuristic risk scoring layer partially mitigates this by preventing a
single keyword indicator from producing a HIGH or CRITICAL result.

**Residual Risk:** A cautious user shown a MEDIUM score for `github.com/login` may
unnecessarily hesitate on a legitimate webpage.

---

## Limitation 8: Possible False Negatives on Novel Phishing Patterns

**Effect:** Phishing URLs that are lexically indistinguishable from legitimate URLs
(short, HTTPS, common TLD, no keywords, no hyphens, no encoding) may not be flagged.
The system's detection capability is bounded by the observable surface of the URL string alone.

---

## Limitation 9: Risk Score is Heuristic and Not Statistically Calibrated

**Status:** The risk score (0–100) is a deterministic heuristic composite metric.
Weights assigned to individual indicators (e.g., IP address domain = +30 points,
suspicious TLD = +25 points) were designed based on cybersecurity reasoning and
Phase 3B validation data, but have not been calibrated using a holdout ground-truth
risk label dataset.

**Effect:** A score of 75/100 does not mean a 75% empirical probability of the URL
being malicious. It means multiple observable phishing-associated structural patterns
were detected in the URL.

---

## Limitation 10: No Multi-Stage Analysis or Behavioral Profiling

**Scope:** PhishGuard currently performs single-pass, stateless URL analysis. There is no
user session history, no behavioral pattern tracking across multiple URL submissions,
and no longitudinal domain reputation scoring.

---

*Document produced as part of PhishGuard 2.0 — Phase 7 Evaluation.*
*All limitations are based on observed, reproducible system behavior or architecture design constraints.*
