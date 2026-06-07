# Phishing URL Detector

**Live demo:** https://huggingface.co/spaces/spinytea/phishing-detector-ml

A machine learning system that flags phishing URLs in real time, with a live web demo.

## What is this

Phishing is when an attacker tricks someone into clicking a fake URL (like paypa1-secure-verify.tk instead of paypal.com) to steal credentials. This project trains a model to spot those fake URLs automatically.

What I built:
- A feature extractor that takes any URL and pulls out 20 numerical signals (length, number of dots, uses an IP instead of a domain, contains suspicious words, how random the domain looks, etc)
- A LightGBM classifier trained on 100,000 labeled URLs (50k phishing, 50k benign)
- A Streamlit web app where anyone can paste a URL and get a phishing risk score plus feature breakdown
- Honest evaluation including failure cases, dataset bias analysis, and a mitigation layer using a domain reputation allowlist

## Why this matters

Phishing is the number one entry point for ransomware and credential theft. Anti-phishing detection is what products like Microsoft Defender, Google Safe Browsing, and most modern EDR tools rely on. This project shows I can build that kind of system from scratch and reason about its weaknesses.

## Results

Trained on 100k balanced URLs, evaluated on a 20k held-out test set.

| Metric | Score |
|--------|-------|
| Accuracy | 93.3% |
| Precision | 93.0% |
| Recall | 93.7% |
| F1 | 93.4% |
| ROC AUC | 0.98 |

Plots in `docs/`: confusion matrix, ROC curve, feature importance.

## Top features the model relies on

1. path_length: phishing URLs often have long suspicious paths
2. num_subdomains: attackers chain subdomains like paypal.com.login-verify.evil.tk
3. num_slashes: structural complexity of the URL
4. domain_entropy: randomly generated domains have high entropy
5. has_https: useful but biased, see Known Limitations below

## Known limitations

Real ML systems fail in interesting ways. Here's what I found and how I handled it.

**Dataset bias:** the training data has older benign URLs that rarely use HTTPS, while the phishing URLs are newer and often do. The model learned a spurious correlation that "modern looking URLs are phishing," which made it flag legitimate sites like github.com as phishing.

**Mitigation:** I added a domain reputation allowlist in the demo app that overrides the model for well-known safe domains. Production anti-phishing systems do the same thing (called reputation-based filtering).

**Better long-term fix:** use the Tranco top-1M domains list as a richer trustlist and re-balance the training data with modern HTTPS-enabled benign URLs from the Common Crawl.

Tech used:

- Python 3.14
- pandas, numpy for data handling
- scikit-learn for splits and metrics
- LightGBM for the classifier
- Streamlit for the web demo
- joblib for model serialization
- matplotlib for plots

Repo structure:

src/ -
features.py        URL feature extraction
build_dataset.py   Builds the training feature matrix from raw URLs
train.py           Trains LightGBM, evaluates, saves model + plots

app/ -
streamlit_app.py     Web demo

models/              Trained model artifacts
docs/                Plots and screenshots

Roadmap:

- [x] Feature extraction
- [x] LightGBM training and evaluation
- [x] Streamlit demo app
- [x] Domain reputation allowlist mitigation
- [x] Live deployment on HuggingFace Spaces
- [ ] Add SHAP per-prediction explanations
- [ ] Add domain-age and WHOIS features via free APIs
- [ ] Retrain on Tranco + Common Crawl for better benign coverage
- [ ] REST API wrapper with FastAPI
