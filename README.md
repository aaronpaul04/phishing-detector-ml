\---

title: Phishing URL Detector

emoji: ðŸŽ£

colorFrom: red

colorTo: orange

sdk: streamlit

sdk\_version: 1.39.0

app\_file: app/streamlit\_app.py

pinned: false

\---



Phishing URL Detector



A machine learning system that flags phishing URLs in real time, with a live web demo and full explainability of how the model decides.



What is this:



Phishing is when an attacker tricks someone into clicking a fake URL (like `paypa1-secure-verify.tk` instead of `paypal.com`) to steal credentials. This project trains a model to spot those fake URLs automatically.



What I built:



\- A feature extractor that takes any URL and pulls out 20 numerical signals (length, number of dots, uses an IP instead of a domain, contains suspicious words like "login" or "verify", how random the domain looks, etc)

\- A LightGBM classifier trained on 100,000 labeled URLs (50k phishing, 50k benign)

\- A Streamlit web app where anyone can paste a URL and get a phishing risk score plus a breakdown of which features were extracted

\- Honest evaluation including failure cases, dataset bias analysis, and a mitigation layer using a domain reputation allowlist



Why this matters:



Phishing is the #1 entry point for ransomware and credential theft. Anti-phishing detection is what products like Microsoft Defender, Google Safe Browsing, and most modern EDR tools rely on. This project shows I can build that kind of system from scratch and reason about its weaknesses.



Results:



Trained on 100k balanced URLs, evaluated on a 20k held-out test set.



Accuracy:  93.3%

Precision: 93.0%

Recall:    93.7%

F1:        93.4%

ROC AUC:   0.98



Plots in `docs/`: confusion matrix, ROC curve, feature importance.



Top features the model relies on:



1\. path\_length - phishing URLs often have long suspicious paths

2\. num\_subdomains - attackers chain subdomains like paypal.com.login-verify.evil.tk

3\. num\_slashes - structural complexity of the URL

4\. domain\_entropy - randomly generated domains have high entropy

5\. has\_https - useful but biased, see Known Limitations below



Known limitations:



Real ML systems fail in interesting ways. Here's what I found and how I handled it.



Dataset bias: the training data has older benign URLs that rarely use HTTPS, while the phishing URLs are newer and often do. The model learned a spurious correlation that "modern looking URLs are phishing," which made it flag legitimate sites like github.com as phishing.



Mitigation: I added a domain reputation allowlist in the demo app that overrides the model for well-known safe domains. Production anti-phishing systems do the same thing (this is called reputation-based filtering).



Better long-term fix: use the Tranco top-1M domains list as a richer trustlist and re-balance the training data with modern HTTPS-enabled benign URLs from the Common Crawl.



This kind of analysis is what real ML engineering looks like, not just "I got 99% accuracy on Kaggle."



Repo structure:



src/

&#x20; features.py        URL feature extraction (20 features)

&#x20; build\_dataset.py   Builds the training feature matrix from raw URLs

&#x20; train.py           Trains LightGBM, evaluates, saves model + plots

app/

&#x20; streamlit\_app.py   Web demo: paste a URL, get a risk score

data/

&#x20; raw/               Original URL dataset (gitignored)

&#x20; processed/         Feature matrix produced by build\_dataset.py

models/              Trained model artifacts (.joblib)

docs/                Plots, screenshots, writeups



Run it yourself:



You need Python 3.10+ and the malicious URLs dataset from Kaggle.



1\. Setup

&#x20;  python -m venv venv

&#x20;  venv\\Scripts\\activate            (Windows)

&#x20;  source venv/bin/activate         (macOS/Linux)

&#x20;  pip install -r requirements.txt



2\. Get the dataset

&#x20;  Download from https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset

&#x20;  Place malicious\_phish.csv in data/raw/



3\. Build features

&#x20;  python src\\build\_dataset.py



4\. Train the model

&#x20;  python src\\train.py



5\. Launch the web app

&#x20;  streamlit run app\\streamlit\_app.py



Tech used:



\- Python 3.14

\- pandas, numpy for data handling

\- scikit-learn for splits and metrics

\- LightGBM for the classifier (gradient boosted trees)

\- Streamlit for the web demo

\- joblib for model serialization

\- matplotlib for plots



Roadmap:



\- \[x] Feature extraction

\- \[x] LightGBM training and evaluation

\- \[x] Streamlit demo app

\- \[x] Domain reputation allowlist mitigation

\- \[ ] Add SHAP per-prediction explanations (running on Colab / HuggingFace)

\- \[ ] Deploy live demo on HuggingFace Spaces

\- \[ ] Add domain-age and WHOIS features via free APIs

\- \[ ] Retrain on Tranco + Common Crawl for better benign coverage

\- \[ ] REST API wrapper with FastAPI



