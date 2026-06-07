"""
Streamlit demo for the phishing URL detector.
Paste a URL, get a risk score plus feature breakdown.
"""

import os
import sys
import joblib
import pandas as pd
import streamlit as st

TRUSTED_DOMAINS = {
    # Tech giants
    "google.com", "youtube.com", "gmail.com", "googleusercontent.com",
    "microsoft.com", "live.com", "outlook.com", "office.com", "bing.com",
    "apple.com", "icloud.com",
    "amazon.com", "amazon.co.uk", "amazon.ae", "amazon.de",
    "meta.com", "facebook.com", "instagram.com", "whatsapp.com", "threads.net",
    "x.com", "twitter.com",
    "linkedin.com", "github.com", "gitlab.com", "bitbucket.org",
    "openai.com", "anthropic.com", "claude.ai", "huggingface.co",
    "cloudflare.com", "akamai.com", "fastly.com",

    # Productivity / dev
    "stackoverflow.com", "stackexchange.com", "medium.com", "dev.to",
    "notion.so", "slack.com", "discord.com", "zoom.us", "teams.microsoft.com",
    "atlassian.com", "jira.com", "trello.com", "figma.com", "canva.com",
    "dropbox.com", "drive.google.com", "onedrive.live.com",
    "npmjs.com", "pypi.org", "docker.com", "kubernetes.io",

    # Search / reference
    "wikipedia.org", "wikimedia.org", "duckduckgo.com", "quora.com",
    "reddit.com", "imgur.com", "pinterest.com", "tumblr.com",

    # Streaming / media
    "netflix.com", "spotify.com", "twitch.tv", "tiktok.com", "vimeo.com",
    "soundcloud.com",

    # News
    "bbc.com", "bbc.co.uk", "cnn.com", "nytimes.com", "theguardian.com",
    "reuters.com", "bloomberg.com", "ft.com", "wsj.com", "aljazeera.com",
    "thenationalnews.com", "khaleejtimes.com", "gulfnews.com",

    # Shopping
    "ebay.com", "etsy.com", "aliexpress.com", "shopify.com", "noon.com",
    "carrefour.com", "ikea.com",

    # Banks / finance (global + UAE)
    "paypal.com", "stripe.com", "wise.com", "revolut.com",
    "hsbc.com", "barclays.com", "chase.com", "bankofamerica.com",
    "emiratesnbd.com", "adcb.com", "fab.ae", "mashreq.com", "rakbank.ae",

    # Education
    "coursera.org", "udemy.com", "edx.org", "khanacademy.org",
    "mit.edu", "stanford.edu", "harvard.edu",

    # UAE / regional
    "etisalat.ae", "du.ae", "dubai.ae", "abudhabi.ae", "uaepass.ae",
    "smartdubai.ae", "moi.gov.ae", "mohre.gov.ae", "ica.gov.ae",

    # Travel
    "booking.com", "airbnb.com", "expedia.com", "emirates.com", "etihad.com",
    "flydubai.com",

    # Misc essentials
    "mozilla.org", "wordpress.com", "wordpress.org", "shopify.com",
    "kaggle.com", "leetcode.com", "hackerrank.com", "hackthebox.com",
    "tryhackme.com", "virustotal.com", "abuseipdb.com",
}

def get_root_domain(url: str) -> str:
    """Best-effort root domain extraction without external libs."""
    from urllib.parse import urlparse
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    try:
        host = urlparse(url).netloc.split(":")[0].lower()
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host
    except Exception:
        return ""

# Make src importable
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, "src"))
from features import extract_features

MODEL_PATH = os.path.join(PROJECT_ROOT, "models", "phishing_lgbm.joblib")


@st.cache_resource
def load_model():
    bundle = joblib.load(MODEL_PATH)
    return bundle["model"], bundle["features"]


def main():
    st.set_page_config(page_title="Phishing URL Detector", page_icon="🎣", layout="centered")
    st.title("Phishing URL Detector")
    st.caption("ML model trained on 100k labeled URLs. Paste a URL to get a phishing risk score.")

    model, feature_names = load_model()

    examples = [
        "https://www.google.com",
        "http://paypa1-secure-verify-account.tk/signin?user=admin",
        "https://github.com/aaronpaul04",
        "http://192.168.0.1/admin/login.php?token=xyz",
    ]

    with st.expander("Try an example URL"):
        for ex in examples:
            if st.button(ex, key=ex):
                st.session_state["url"] = ex

    url = st.text_input(
        "URL to analyze",
        value=st.session_state.get("url", ""),
        placeholder="https://example.com/login",
    )

    if not url:
        st.info("Enter a URL above to get started.")
        return

    feats = extract_features(url)
    X = pd.DataFrame([feats])[feature_names]
    proba = float(model.predict_proba(X)[0, 1])
    root = get_root_domain(url)
    on_trustlist = root in TRUSTED_DOMAINS

    if on_trustlist:
        label = "BENIGN"
        proba = min(proba, 0.05)  # cap at 5% if whitelisted
    else:
        label = "PHISHING" if proba >= 0.5 else "BENIGN"

    # Verdict
    col1, col2 = st.columns(2)
    with col1:
        if label == "PHISHING":
            st.error(f"### {label}")
        else:
            st.success(f"### {label}")
    with col2:
        st.metric("Risk score", f"{proba * 100:.1f}%")

    st.progress(proba)

    # Feature breakdown
    st.subheader("Extracted features")
    feat_df = pd.DataFrame({
        "Feature": list(feats.keys()),
        "Value": list(feats.values()),
    })
    st.dataframe(feat_df, use_container_width=True, hide_index=True)

    # Top model features driving its overall logic
    st.subheader("Most important features (model-wide)")
    importance = pd.DataFrame({
        "Feature": feature_names,
        "Gain importance": model.booster_.feature_importance(importance_type="gain"),
    }).sort_values("Gain importance", ascending=False).head(10)
    st.dataframe(importance, use_container_width=True, hide_index=True)

    st.markdown("---")
    st.caption(
        "Built with LightGBM + Streamlit. "
        "Model: 100k URLs, 93% accuracy, 0.98 ROC AUC. "
        "[GitHub repo](https://github.com/aaronpaul04/phishing-detector-ml)"
    )


if __name__ == "__main__":
    main()